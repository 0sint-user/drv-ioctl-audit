#include "ioctl_audit.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace drv_audit {
namespace {

struct RiskRule {
    const char* symbol;
    Severity severity;
    const char* category;
    const char* note;
};

constexpr RiskRule kRiskRules[] = {
    {"MmMapIoSpace", Severity::High, "physical_memory", "Maps physical memory into kernel VA space"},
    {"MmMapIoSpaceEx", Severity::High, "physical_memory", "Maps physical memory with explicit page protection"},
    {"MmGetPhysicalAddress", Severity::Medium, "physical_memory", "Translates virtual address to physical address"},
    {"ZwMapViewOfSection", Severity::High, "section_mapping", "Can map \\Device\\PhysicalMemory if paired with ZwOpenSection"},
    {"ZwOpenSection", Severity::Medium, "section_mapping", "Opens named kernel section objects"},
    {"MmCopyMemory", Severity::Medium, "memory_access", "Copies arbitrary virtual or physical memory ranges"},
    {"HalGetBusData", Severity::High, "pci_bus_io", "Legacy PCI/bus configuration read primitive"},
    {"HalGetBusDataByOffset", Severity::High, "pci_bus_io", "Legacy PCI/bus configuration read primitive"},
    {"HalSetBusData", Severity::High, "pci_bus_io", "Legacy PCI/bus configuration write primitive"},
    {"HalSetBusDataByOffset", Severity::High, "pci_bus_io", "Legacy PCI/bus configuration write primitive"},
    {"MmAllocateContiguousMemory", Severity::Medium, "dma_alloc", "Allocates physically contiguous memory"},
    {"ZwOpenProcess", Severity::Medium, "process_access", "Kernel-mode process handle open"},
    {"PsLookupProcessByProcessId", Severity::Info, "process_access", "Resolves EPROCESS from PID"},
    {"MmCopyVirtualMemory", Severity::High, "process_access", "Cross-process virtual memory R/W primitive"},
};

bool is_candidate_ioctl(uint32_t code, uint16_t& dev_type, uint16_t& func, uint8_t& method, uint8_t& access) {
    method = static_cast<uint8_t>(code & 0x3u);
    func = static_cast<uint16_t>((code >> 2) & 0xFFFu);
    access = static_cast<uint8_t>((code >> 14) & 0x3u);
    dev_type = static_cast<uint16_t>((code >> 16) & 0xFFFFu);

    // Custom vendor device types start at 0x8000; FILE_DEVICE_UNKNOWN is 0x0022.
    const bool plausible_device = (dev_type >= 0x8000u && dev_type <= 0xFFFFu) || dev_type == 0x0022u;
    const bool plausible_func = func >= 0x800u; // Microsoft reserves < 0x800 for standard functions
    if (!plausible_device || !plausible_func) {
        return false;
    }

    // Highlight METHOD_NEITHER (3) or FILE_ANY_ACCESS (0) on custom device types.
    return method == 3 || access == 0;
}

} // namespace

AuditReport audit_driver(const PeImage& image, std::span<const uint8_t> raw_bytes) {
    AuditReport report;
    report.is_native_subsystem = (image.subsystem == 1); // IMAGE_SUBSYSTEM_NATIVE

    for (const auto& imp : image.imports) {
        if (imp.by_ordinal || imp.function_name.empty()) {
            continue;
        }
        if (imp.function_name == "IoCreateDevice") {
            report.uses_io_create_device = true;
        } else if (imp.function_name == "IoCreateDeviceSecure") {
            report.uses_io_create_device_secure = true;
        }

        for (const auto& rule : kRiskRules) {
            if (imp.function_name == rule.symbol) {
                report.import_findings.push_back(ImportFinding{
                    imp.dll_name,
                    imp.function_name,
                    rule.severity,
                    rule.category,
                    rule.note,
                });
                break;
            }
        }
    }

    std::unordered_set<uint32_t> seen_codes;
    for (const auto& sec : image.sections) {
        if (!sec.is_executable() && sec.name != ".rdata") {
            continue;
        }
        if (sec.raw_offset >= raw_bytes.size() || sec.raw_size < 4) {
            continue;
        }
        const size_t max_avail = raw_bytes.size() - sec.raw_offset;
        const size_t scan_len = std::min(static_cast<size_t>(sec.raw_size), max_avail);
        if (scan_len < 4) {
            continue;
        }

        for (size_t i = 0; i <= scan_len - 4; ++i) {
            uint32_t val = 0;
            std::memcpy(&val, raw_bytes.data() + sec.raw_offset + i, 4);

            uint16_t dev_type = 0;
            uint16_t func = 0;
            uint8_t method = 0;
            uint8_t access = 0;
            if (!is_candidate_ioctl(val, dev_type, func, method, access)) {
                continue;
            }
            if (!seen_codes.insert(val).second) {
                continue;
            }
            report.ioctl_candidates.push_back(IoctlCandidate{
                val,
                dev_type,
                func,
                method,
                access,
                sec.name,
                static_cast<uint32_t>(sec.raw_offset + i),
            });
        }
    }

    return report;
}

const char* severity_to_string(Severity s) {
    switch (s) {
    case Severity::Info:
        return "INFO";
    case Severity::Medium:
        return "MEDIUM";
    case Severity::High:
        return "HIGH";
    }
    return "UNKNOWN";
}

const char* method_to_string(uint8_t method) {
    switch (method) {
    case 0:
        return "METHOD_BUFFERED";
    case 1:
        return "METHOD_IN_DIRECT";
    case 2:
        return "METHOD_OUT_DIRECT";
    case 3:
        return "METHOD_NEITHER";
    default:
        return "UNKNOWN";
    }
}

const char* access_to_string(uint8_t access) {
    switch (access) {
    case 0:
        return "FILE_ANY_ACCESS";
    case 1:
        return "FILE_READ_ACCESS";
    case 2:
        return "FILE_WRITE_ACCESS";
    case 3:
        return "FILE_READ_WRITE_ACCESS";
    default:
        return "UNKNOWN";
    }
}

} // namespace drv_audit
