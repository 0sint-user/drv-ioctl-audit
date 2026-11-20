#include "pe_parser.hpp"

#include <algorithm>
#include <cstring>

namespace drv_audit {
namespace {

constexpr uint16_t kDosMagic = 0x5A4D;       // "MZ"
constexpr uint32_t kPeSignature = 0x00004550; // "PE\0\0"
constexpr uint16_t kOptMagic32 = 0x010B;
constexpr uint16_t kOptMagic64 = 0x020B;
constexpr uint32_t kMaxSections = 96;
constexpr uint32_t kMaxImportDescriptors = 512;
constexpr uint32_t kMaxThunksPerDll = 8192;

template <typename T>
bool read_pod(std::span<const uint8_t> data, size_t offset, T& out) {
    if (offset > data.size() || sizeof(T) > data.size() - offset) {
        return false;
    }
    std::memcpy(&out, data.data() + offset, sizeof(T));
    return true;
}

std::string read_cstr(std::span<const uint8_t> data, size_t offset, size_t max_len = 256) {
    if (offset >= data.size()) {
        return {};
    }
    const size_t limit = std::min(data.size() - offset, max_len);
    std::string result;
    result.reserve(64);
    for (size_t i = 0; i < limit; ++i) {
        const char ch = static_cast<char>(data[offset + i]);
        if (ch == '\0') {
            break;
        }
        result.push_back(ch);
    }
    return result;
}

#pragma pack(push, 1)
struct RawFileHeader {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
};

struct RawDataDirectory {
    uint32_t virtual_address;
    uint32_t size;
};

struct RawSectionHeader {
    char name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_linenumbers;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
    uint32_t characteristics;
};

struct RawImportDescriptor {
    uint32_t original_first_thunk;
    uint32_t time_date_stamp;
    uint32_t forwarder_chain;
    uint32_t name_rva;
    uint32_t first_thunk;
};
#pragma pack(pop)

} // namespace

std::optional<uint32_t> PeImage::rva_to_offset(uint32_t rva) const {
    for (const auto& sec : sections) {
        const uint32_t span_size = std::max(sec.virtual_size, sec.raw_size);
        if (span_size == 0) {
            continue;
        }
        if (rva >= sec.virtual_address && (rva - sec.virtual_address) < span_size) {
            const uint32_t delta = rva - sec.virtual_address;
            if (delta < sec.raw_size) {
                return sec.raw_offset + delta;
            }
            return std::nullopt;
        }
    }
    return std::nullopt;
}

PeParseResult parse_pe(std::span<const uint8_t> data) {
    PeParseResult res;
    uint16_t dos_magic = 0;
    if (!read_pod(data, 0, dos_magic) || dos_magic != kDosMagic) {
        res.error = "missing MZ header";
        return res;
    }

    uint32_t lfanew = 0;
    if (!read_pod(data, 0x3C, lfanew) || lfanew > data.size()) {
        res.error = "invalid e_lfanew";
        return res;
    }

    uint32_t pe_sig = 0;
    if (!read_pod(data, lfanew, pe_sig) || pe_sig != kPeSignature) {
        res.error = "missing PE signature";
        return res;
    }

    RawFileHeader fh{};
    const size_t fh_off = static_cast<size_t>(lfanew) + 4;
    if (!read_pod(data, fh_off, fh)) {
        res.error = "truncated COFF header";
        return res;
    }
    if (fh.number_of_sections > kMaxSections) {
        res.error = "implausible section count";
        return res;
    }

    const size_t opt_off = fh_off + sizeof(RawFileHeader);
    uint16_t opt_magic = 0;
    if (!read_pod(data, opt_off, opt_magic)) {
        res.error = "truncated optional header";
        return res;
    }

    PeImage img;
    img.machine = fh.machine;
    img.timestamp = fh.time_date_stamp;

    uint32_t num_rva_sizes = 0;
    size_t data_dir_off = 0;

    if (opt_magic == kOptMagic64) {
        img.is_64bit = true;
        if (!read_pod(data, opt_off + 16, img.entry_point_rva) ||
            !read_pod(data, opt_off + 24, img.image_base) ||
            !read_pod(data, opt_off + 68, img.subsystem) ||
            !read_pod(data, opt_off + 108, num_rva_sizes)) {
            res.error = "truncated PE32+ optional header";
            return res;
        }
        data_dir_off = opt_off + 112;
    } else if (opt_magic == kOptMagic32) {
        img.is_64bit = false;
        uint32_t base32 = 0;
        if (!read_pod(data, opt_off + 16, img.entry_point_rva) ||
            !read_pod(data, opt_off + 28, base32) ||
            !read_pod(data, opt_off + 68, img.subsystem) ||
            !read_pod(data, opt_off + 92, num_rva_sizes)) {
            res.error = "truncated PE32 optional header";
            return res;
        }
        img.image_base = base32;
        data_dir_off = opt_off + 96;
    } else {
        res.error = "unsupported optional header magic";
        return res;
    }

    const size_t sec_off = opt_off + fh.size_of_optional_header;
    img.sections.reserve(fh.number_of_sections);
    for (uint16_t i = 0; i < fh.number_of_sections; ++i) {
        RawSectionHeader raw_sec{};
        if (!read_pod(data, sec_off + static_cast<size_t>(i) * sizeof(RawSectionHeader), raw_sec)) {
            res.error = "truncated section header";
            return res;
        }
        PeSection sec;
        size_t name_len = 0;
        while (name_len < 8 && raw_sec.name[name_len] != '\0') {
            ++name_len;
        }
        sec.name.assign(raw_sec.name, name_len);
        sec.virtual_address = raw_sec.virtual_address;
        sec.virtual_size = raw_sec.virtual_size;
        sec.raw_offset = raw_sec.pointer_to_raw_data;
        sec.raw_size = raw_sec.size_of_raw_data;
        sec.characteristics = raw_sec.characteristics;
        img.sections.push_back(std::move(sec));
    }

    if (num_rva_sizes >= 2) {
        RawDataDirectory import_dir{};
        if (read_pod(data, data_dir_off + sizeof(RawDataDirectory), import_dir) &&
            import_dir.virtual_address != 0) {
            if (auto imp_off = img.rva_to_offset(import_dir.virtual_address)) {
                for (uint32_t d = 0; d < kMaxImportDescriptors; ++d) {
                    RawImportDescriptor desc{};
                    const size_t desc_off = *imp_off + static_cast<size_t>(d) * sizeof(RawImportDescriptor);
                    if (!read_pod(data, desc_off, desc)) {
                        break;
                    }
                    if (desc.name_rva == 0 && desc.first_thunk == 0) {
                        break;
                    }
                    auto dll_off = img.rva_to_offset(desc.name_rva);
                    if (!dll_off) {
                        continue;
                    }
                    std::string dll_name = read_cstr(data, *dll_off);
                    const uint32_t thunk_rva =
                        desc.original_first_thunk != 0 ? desc.original_first_thunk : desc.first_thunk;
                    auto thunk_off = img.rva_to_offset(thunk_rva);
                    if (!thunk_off) {
                        continue;
                    }

                    for (uint32_t t = 0; t < kMaxThunksPerDll; ++t) {
                        if (img.is_64bit) {
                            uint64_t val = 0;
                            if (!read_pod(data, *thunk_off + static_cast<size_t>(t) * 8, val) || val == 0) {
                                break;
                            }
                            PeImport imp;
                            imp.dll_name = dll_name;
                            if ((val & (1ULL << 63)) != 0) {
                                imp.by_ordinal = true;
                                imp.ordinal = static_cast<uint16_t>(val & 0xFFFFu);
                            } else {
                                auto hint_off = img.rva_to_offset(static_cast<uint32_t>(val & 0x7FFFFFFFu));
                                if (hint_off) {
                                    imp.function_name = read_cstr(data, *hint_off + 2);
                                }
                            }
                            img.imports.push_back(std::move(imp));
                        } else {
                            uint32_t val = 0;
                            if (!read_pod(data, *thunk_off + static_cast<size_t>(t) * 4, val) || val == 0) {
                                break;
                            }
                            PeImport imp;
                            imp.dll_name = dll_name;
                            if ((val & (1u << 31)) != 0) {
                                imp.by_ordinal = true;
                                imp.ordinal = static_cast<uint16_t>(val & 0xFFFFu);
                            } else {
                                auto hint_off = img.rva_to_offset(val & 0x7FFFFFFFu);
                                if (hint_off) {
                                    imp.function_name = read_cstr(data, *hint_off + 2);
                                }
                            }
                            img.imports.push_back(std::move(imp));
                        }
                    }
                }
            }
        }
    }

    res.image = std::move(img);
    return res;
}

} // namespace drv_audit
