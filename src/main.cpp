#include "ioctl_audit.hpp"
#include "pe_parser.hpp"

#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace {

bool read_file_bytes(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        return false;
    }
    const auto size = ifs.tellg();
    if (size <= 0) {
        return false;
    }
    out.resize(static_cast<size_t>(size));
    ifs.seekg(0, std::ios::beg);
    return static_cast<bool>(ifs.read(reinterpret_cast<char*>(out.data()), size));
}

void print_json(const drv_audit::PeImage& img, const drv_audit::AuditReport& rep) {
    std::cout << "{\n";
    std::cout << "  \"is_64bit\": " << (img.is_64bit ? "true" : "false") << ",\n";
    std::cout << "  \"native_subsystem\": " << (rep.is_native_subsystem ? "true" : "false") << ",\n";
    std::cout << "  \"io_create_device\": " << (rep.uses_io_create_device ? "true" : "false") << ",\n";
    std::cout << "  \"io_create_device_secure\": " << (rep.uses_io_create_device_secure ? "true" : "false") << ",\n";
    std::cout << "  \"import_findings\": [\n";
    for (size_t i = 0; i < rep.import_findings.size(); ++i) {
        const auto& f = rep.import_findings[i];
        std::cout << "    {\"module\": \"" << f.module_name << "\", \"symbol\": \"" << f.symbol_name
                  << "\", \"severity\": \"" << drv_audit::severity_to_string(f.severity)
                  << "\", \"category\": \"" << f.category << "\"}";
        if (i + 1 < rep.import_findings.size()) {
            std::cout << ",";
        }
        std::cout << "\n";
    }
    std::cout << "  ],\n";
    std::cout << "  \"ioctl_candidates\": [\n";
    for (size_t i = 0; i < rep.ioctl_candidates.size(); ++i) {
        const auto& c = rep.ioctl_candidates[i];
        std::cout << "    {\"code\": \"0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << c.code << std::dec << "\", \"method\": \"" << drv_audit::method_to_string(c.method)
                  << "\", \"access\": \"" << drv_audit::access_to_string(c.access) << "\", \"offset\": "
                  << c.file_offset << "}";
        if (i + 1 < rep.ioctl_candidates.size()) {
            std::cout << ",";
        }
        std::cout << "\n";
    }
    std::cout << "  ]\n";
    std::cout << "}\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: drv-ioctl-audit <driver.sys> [--json]\n";
        return 1;
    }

    const std::string path = argv[1];
    const bool json_mode = (argc >= 3 && std::string(argv[2]) == "--json");

    std::vector<uint8_t> data;
    if (!read_file_bytes(path, data)) {
        std::cerr << "Error: failed to read " << path << "\n";
        return 1;
    }

    auto parsed = drv_audit::parse_pe(data);
    if (!parsed.image) {
        std::cerr << "Error: PE parse failed: " << parsed.error << "\n";
        return 1;
    }

    const auto& img = *parsed.image;
    const auto report = drv_audit::audit_driver(img, data);

    if (json_mode) {
        print_json(img, report);
        return 0;
    }

    std::cout << "Arch: " << (img.is_64bit ? "x64" : "x86")
              << " | Native subsystem: " << (report.is_native_subsystem ? "yes" : "no")
              << " | Sections: " << img.sections.size()
              << " | Imports: " << img.imports.size() << "\n";

    if (report.uses_io_create_device && !report.uses_io_create_device_secure) {
        std::cout << "[WARN] Uses IoCreateDevice without IoCreateDeviceSecure (check device ACLs)\n";
    }

    std::cout << "\nImport findings (" << report.import_findings.size() << "):\n";
    for (const auto& f : report.import_findings) {
        std::cout << "  [" << drv_audit::severity_to_string(f.severity) << "] "
                  << f.module_name << "!" << f.symbol_name
                  << " (" << f.category << ") - " << f.note << "\n";
    }

    std::cout << "\nCandidate IOCTLs (" << report.ioctl_candidates.size() << "):\n";
    for (const auto& c : report.ioctl_candidates) {
        std::cout << "  0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << c.code
                  << "  dev=0x" << std::setw(4) << c.device_type
                  << " func=0x" << std::setw(3) << c.function_code << std::dec
                  << "  " << drv_audit::method_to_string(c.method)
                  << "  " << drv_audit::access_to_string(c.access)
                  << "  (" << c.section_name << " @ 0x" << std::hex << c.file_offset << std::dec << ")\n";
    }

    return 0;
}
