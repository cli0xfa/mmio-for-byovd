# Compatibility matrix

| Target | Status | Evidence |
|---|---|---|
| Windows x64, MSVC C++20 | Intended | Windows header smoke target and CI matrix; awaiting CI execution |
| Windows x64, MSVC C++23 | Intended | Windows header smoke target and CI matrix; awaiting CI execution |
| Windows 10/11 and Server runtime | Expected, not environment-tested | Requires an authorized Windows VM and a compatible mapping backend |
| Linux driver-free model tests | Verified locally with GCC C++20 | `tests/test_paging_model.cpp` |
| x86 and ARM64 | Unsupported | The implementation requires x64 paging and MSVC SEH |
| VBS/HVCI, vulnerable-driver blocklist, Hyper-V layouts | Not claimed | No bypass behavior; failures depend on system policy and backend |

The legacy range estimate remains available for source compatibility, but does not model physical address holes. Supply `FnGetPhysicalRanges` for exact scan coverage.
