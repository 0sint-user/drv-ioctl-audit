#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace drv_audit {

struct PeSection {
    std::string name;
    uint32_t virtual_address = 0;
    uint32_t virtual_size = 0;
    uint32_t raw_offset = 0;
    uint32_t raw_size = 0;
    uint32_t characteristics = 0;

    bool is_executable() const { return (characteristics & 0x20000000u) != 0; }
    bool is_readable() const { return (characteristics & 0x40000000u) != 0; }
    bool is_writable() const { return (characteristics & 0x80000000u) != 0; }
};

struct PeImport {
    std::string dll_name;
    std::string function_name;
    uint16_t ordinal = 0;
    bool by_ordinal = false;
};

struct PeImage {
    bool is_64bit = false;
    uint16_t machine = 0;
    uint16_t subsystem = 0;
    uint32_t entry_point_rva = 0;
    uint64_t image_base = 0;
    uint32_t timestamp = 0;
    std::vector<PeSection> sections;
    std::vector<PeImport> imports;

    std::optional<uint32_t> rva_to_offset(uint32_t rva) const;
};

struct PeParseResult {
    std::optional<PeImage> image;
    std::string error;
};

PeParseResult parse_pe(std::span<const uint8_t> data);

} // namespace drv_audit
