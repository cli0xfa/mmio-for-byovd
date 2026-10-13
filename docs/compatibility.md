# Compatibility matrix

| Target | Status | Evidence |
|---|---|---|
| Windows x64, MSVC C++20 | CI verified | [Actions run 38352827466](https://github.com/cli0xfa/mmio-for-byovd/actions/runs/38352827466), commit `bd15a388afa408436c57c0a7e1514dec53057b1e`; Debug and Release passed |
| Windows x64, MSVC C++23 | CI verified | [Actions run 38352827466](https://github.com/cli0xfa/mmio-for-byovd/actions/runs/38352827466), commit `bd15a388afa408436c57c0a7e1514dec53057b1e`; Debug and Release passed |
| Windows 10/11 and Server runtime | Expected, not environment-tested | Requires an authorized Windows VM and a compatible mapping backend |
| Linux driver-free model tests | Verified locally with GCC C++20 | `tests/test_paging_model.cpp`, `tests/test_driver_enumeration_model.cpp` |
| x86 and ARM64 | Unsupported | The implementation requires x64 paging and MSVC SEH |
| VBS/HVCI, vulnerable-driver blocklist, Hyper-V layouts | Not claimed | No bypass behavior; failures depend on system policy and backend |

The legacy range estimate remains available for source compatibility, but does not model physical address holes. Supply `FnGetPhysicalRanges` for exact scan coverage.

The Windows CI result covers compilation, the public-header smoke test, static analysis enabled for that target, and driver-free CTest. It does not validate loading a driver, a real physical-memory mapping backend, or runtime compatibility across Windows releases and security configurations.
