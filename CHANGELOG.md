# Changelog

## Unreleased

- Extracted a platform-independent page-table model for repeatable synthetic tests.
- Reject ambiguous paging-mode inference and validate 4-level and 5-level candidates against the kernel PE signature.
- Added optional exact physical-range enumeration for CR3 scanning.
- Tightened parameter, initialization, and mapping-lifetime behavior; documented partial-operation semantics.
- Added driver-free tests and Windows Debug/Release CI.
- Source compatibility: `Mmio` is now move-only because it owns a HANDLE and mapping callbacks. Replace copies with `std::move` or create a separate borrowed-handle instance.
