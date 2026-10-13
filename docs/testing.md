# Testing

The default CMake test set is driver-free. It covers canonical address checks, 4-level and 5-level synthetic page tables, 4 KB/2 MB/1 GB mappings, missing and non-present entries, reserved bits, physical range normalization, integer boundaries, and driver-enumeration buffer growth/shrinkage, changing lists, malformed sizes, API failures, and unique kernel-image selection.

On Windows, `mmio_windows_header_smoke` compiles and runs the public header with synthetic page tables and fault-injected callbacks. It covers mapping rejection, invalid mappings, guarded copy faults, cleanup exceptions, move ownership, and partial operations. The smoke target enables MSVC `/analyze`. CI builds Debug and Release configurations in C++20 and C++23 and runs only driver-free tests. It does not load, install, or distribute the embedded WinIo integration driver.

The `integration/winio/test.vcxproj` executable is an opt-in integration harness and installs a driver service. Run it only in an authorized disposable Windows VM with a snapshot. It is not part of CI.
