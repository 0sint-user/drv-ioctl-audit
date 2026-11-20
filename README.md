# drv-ioctl-audit

Static PE32/PE32+ auditor for Windows kernel drivers (`.sys`).

Parses section tables, import descriptors, and code/rdata constants to flag common BYOVD / driver attack surface indicators before opening a binary in IDA or WinDbg:

- Dangerous kernel imports (`MmMapIoSpace`, `MmMapIoSpaceEx`, `ZwMapViewOfSection`, `ZwOpenSection`, `HalGetBusData*`, `MmGetPhysicalAddress`, etc.)
- `IoCreateDevice` vs `IoCreateDeviceSecure` usage
- Candidate `CTL_CODE` 32-bit constants using `METHOD_NEITHER` (transfer type 3) or `FILE_ANY_ACCESS` (access 0) with custom device types (`0x8000+`)

## Build

Requires a C++20 compiler and CMake 3.20+.

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure
```

## Usage

```sh
./build/drv-ioctl-audit path/to/driver.sys
./build/drv-ioctl-audit path/to/driver.sys --json
```

## Notes

- Static heuristic only: candidate `CTL_CODE` values are 32-bit aligned/unaligned constants matching standard `CTL_CODE(DeviceType, Function, Method, Access)` bitfields. Always verify against `IRP_MJ_DEVICE_CONTROL` in a disassembler.
- No Windows headers required to build; runs on Windows, Linux, and macOS.
