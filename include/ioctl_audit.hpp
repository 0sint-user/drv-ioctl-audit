#pragma once

#include "pe_parser.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace drv_audit {

enum class Severity {
    Info,
    Medium,
    High
};

struct ImportFinding {
    std::string module_name;
    std::string symbol_name;
    Severity severity = Severity::Info;
    std::string category;
    std::string note;
};

struct IoctlCandidate {
    uint32_t code = 0;
    uint16_t device_type = 0;
    uint16_t function_code = 0;
    uint8_t method = 0;
    uint8_t access = 0;
    std::string section_name;
    uint32_t file_offset = 0;
};

struct AuditReport {
    bool is_native_subsystem = false;
    bool uses_io_create_device = false;
    bool uses_io_create_device_secure = false;
    std::vector<ImportFinding> import_findings;
    std::vector<IoctlCandidate> ioctl_candidates;
};

AuditReport audit_driver(const PeImage& image, std::span<const uint8_t> raw_bytes);

const char* severity_to_string(Severity s);
const char* method_to_string(uint8_t method);
const char* access_to_string(uint8_t access);

} // namespace drv_audit
