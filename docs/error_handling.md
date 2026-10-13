# Error handling

`last_status()` and `last_error()` describe the most recent operation on an instance. They are mutable per-operation state, so they must not be read concurrently with another operation on the same object.

| Status | Meaning |
|---|---|
| `InvalidArgument` | Invalid pointer, zero length, overflowing address interval, invalid mapping result, or invalid physical range |
| `BadCallbacks` | Required map/unmap callbacks are missing |
| `NotInitialized` | A cached-CR3 operation was requested before successful initialization |
| `UnsupportedPagingMode` | The active paging mode could not be uniquely established |
| `MappingFailed` | The mapping backend rejected a physical mapping request |
| `TranslationFailed` | A page-table entry was absent or reserved, or its address could not be translated |
| `PhysicalRangesUnavailable` | The exact range provider failed or returned no ranges |
| `NoKernelBase` / `NoSystemCr3` | OS kernel enumeration or CR3 validation found no usable result |
| `NoSeDebugPrivilege` | Kernel driver enumeration was denied because SeDebugPrivilege was unavailable |
| `AccessDenied` | A Windows API denied access for another privilege or policy reason |
| `Cancelled` | The scan progress callback requested cancellation |
| `InternalError` | A range provider or progress callback threw, or a guarded copy raised an access violation |

Windows API failures preserve `GetLastError()` where the failing API supplies a useful code. Callback interfaces return only `bool`/`void`, so backend-specific error codes are not available through the current callback signatures.

A detailed multi-page operation counts only page segments that completed in full. It does not count a segment whose copy faults part way through. Earlier completed segments are not rolled back.
