#include "ioctl_audit.hpp"
#include "pe_parser.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

namespace {

void write_u16(std::vector<uint8_t>& buf, size_t off, uint16_t v) {
    std::memcpy(buf.data() + off, &v, 2);
}

void write_u32(std::vector<uint8_t>& buf, size_t off, uint32_t v) {
    std::memcpy(buf.data() + off, &v, 4);
}

void write_u64(std::vector<uint8_t>& buf, size_t off, uint64_t v) {
    std::memcpy(buf.data() + off, &v, 8);
}

// Builds a minimal valid PE32+ (.sys) image in memory with:
// - .text section at RVA 0x1000 / raw 0x200 containing a CTL_CODE constant
// - .rdata section at RVA 0x2000 / raw 0x400 containing ntoskrnl.exe imports
std::vector<uint8_t> build_synthetic_sys() {
    std::vector<uint8_t> pe(0x600, 0);

    // DOS header
    write_u16(pe, 0x00, 0x5A4D);
    write_u32(pe, 0x3C, 0x80);

    // PE signature + COFF header (at 0x80)
    write_u32(pe, 0x80, 0x00004550);
    write_u16(pe, 0x84, 0x8664); // AMD64
    write_u16(pe, 0x86, 2);      // 2 sections
    write_u16(pe, 0x94, 0xF0);   // SizeOfOptionalHeader

    // Optional header PE32+ (at 0x98)
    const size_t opt = 0x98;
    write_u16(pe, opt + 0, 0x020B);      // PE32+
    write_u32(pe, opt + 16, 0x1000);     // AddressOfEntryPoint
    write_u64(pe, opt + 24, 0x140000000ULL);
    write_u16(pe, opt + 68, 1);          // IMAGE_SUBSYSTEM_NATIVE
    write_u32(pe, opt + 108, 16);        // NumberOfRvaAndSizes

    // DataDirectory[1] = Import Table at opt + 112 + 8
    write_u32(pe, opt + 120, 0x2000);    // Import RVA
    write_u32(pe, opt + 124, 40);

    // Section headers at opt + 0xF0 = 0x188
    const size_t sec0 = opt + 0xF0;
    std::memcpy(pe.data() + sec0, ".text\0\0\0", 8);
    write_u32(pe, sec0 + 8, 0x200);
    write_u32(pe, sec0 + 12, 0x1000);
    write_u32(pe, sec0 + 16, 0x200);
    write_u32(pe, sec0 + 20, 0x200);
    write_u32(pe, sec0 + 36, 0x60000020); // CODE | EXECUTE | READ

    const size_t sec1 = sec0 + 40;
    std::memcpy(pe.data() + sec1, ".rdata\0\0", 8);
    write_u32(pe, sec1 + 8, 0x200);
    write_u32(pe, sec1 + 12, 0x2000);
    write_u32(pe, sec1 + 16, 0x200);
    write_u32(pe, sec1 + 20, 0x400);
    write_u32(pe, sec1 + 36, 0x40000040); // INITIALIZED_DATA | READ

    // Embed CTL_CODE(0x8000, 0x801, METHOD_NEITHER=3, FILE_ANY_ACCESS=0) = 0x80002007 in .text
    constexpr uint32_t kIoctl = (0x8000u << 16) | (0u << 14) | (0x801u << 2) | 3u;
    write_u32(pe, 0x210, kIoctl);

    // Build import descriptor in .rdata (raw 0x400 == RVA 0x2000)
    // Descriptor[0] at 0x400 (20 bytes), Descriptor[1] null at 0x414
    write_u32(pe, 0x400 + 0, 0x2040);  // OriginalFirstThunk
    write_u32(pe, 0x400 + 12, 0x2030); // Name RVA ("ntoskrnl.exe")
    write_u32(pe, 0x400 + 16, 0x2040); // FirstThunk

    std::memcpy(pe.data() + 0x430, "ntoskrnl.exe\0", 13);

    // Thunks at raw 0x440 (RVA 0x2040): 2 entries + null
    write_u64(pe, 0x440, 0x2060);
    write_u64(pe, 0x448, 0x2080);
    write_u64(pe, 0x450, 0);

    // Hint/Name at RVA 0x2060 (raw 0x460): "MmMapIoSpace"
    write_u16(pe, 0x460, 0);
    std::memcpy(pe.data() + 0x462, "MmMapIoSpace\0", 13);

    // Hint/Name at RVA 0x2080 (raw 0x480): "IoCreateDevice"
    write_u16(pe, 0x480, 0);
    std::memcpy(pe.data() + 0x482, "IoCreateDevice\0", 15);

    return pe;
}

} // namespace

int main() {
    const auto pe = build_synthetic_sys();
    const auto parsed = drv_audit::parse_pe(pe);
    assert(parsed.image.has_value());

    const auto& img = *parsed.image;
    assert(img.is_64bit);
    assert(img.sections.size() == 2);
    assert(img.imports.size() == 2);

    const auto rep = drv_audit::audit_driver(img, pe);
    assert(rep.is_native_subsystem);
    assert(rep.uses_io_create_device);
    assert(!rep.uses_io_create_device_secure);
    assert(rep.import_findings.size() == 1);
    assert(rep.import_findings[0].symbol_name == "MmMapIoSpace");
    assert(rep.import_findings[0].severity == drv_audit::Severity::High);

    assert(rep.ioctl_candidates.size() == 1);
    assert(rep.ioctl_candidates[0].code == 0x80002007u);
    assert(rep.ioctl_candidates[0].method == 3);
    assert(rep.ioctl_candidates[0].access == 0);

    std::cout << "test_audit passed\n";
    return 0;
}
