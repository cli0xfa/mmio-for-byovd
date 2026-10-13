# API contract

## Mapping callbacks

`FnMap` receives a page-aligned physical base, a pointer for the returned user virtual address, and a nonzero length. It returns `true` only when the mapping is live and must then provide a nonzero, non-overflowing user address range. Any `true` result transfers one cleanup obligation to `Mmio`, including an invalid zero or overflowing output; `FnUnMap` is attempted exactly once on every exit path, so a zero output results in an `FnUnMap(0)` attempt. The library validates the output before dereferencing it. A `false` result must not leave a live mapping. Callbacks should not throw and must support nested calls. `FnUnMap` has a `void` signature, so cleanup failure cannot be reported through `MmioStatus`; exceptions are swallowed and cleanup is best effort.

`FnGetPhysicalRanges` is optional for source compatibility. When supplied, it must return the physical address ranges that the mapping backend is allowed to map. Every base and length must be 4 KB aligned, nonzero, fit within CPUID `MAXPHYADDR`, and form a non-overflowing half-open interval. The library sorts and merges overlapping or adjacent ranges before scanning. Without the provider, the legacy installed-capacity estimate is used and can miss memory above holes or remapped ranges.

All address ranges use `[address, address + size)`. The exclusive end must be representable as a `uint64_t`; therefore `[UINT64_MAX - 1, UINT64_MAX)` is valid, while a one-byte range starting at `UINT64_MAX` is rejected because its exclusive end would wrap.

## Memory operations

All read and write methods reject zero length, null buffers, and overflowing ranges with `InvalidArgument` before invoking `FnMap`. Physical reads and writes accept at most one two-page window; kernel operations split work at 4 KB boundaries. The bool methods and three-argument detailed methods use the cached System CR3 and require successful `Initialize()`. The five-argument detailed overloads can run without cached initialization when given a nonzero CR3 and an explicit paging mode.

The `bool` result reports whether the whole request completed. If a multi-page operation fails part way through, prior segments remain completed and are not rolled back. `ReadKernelMemoryDetailed` and `WriteKernelMemoryDetailed` report bytes in fully completed page segments, meaning bytes the library confirmed completed. A fault part way through the current segment is not counted, even though a write fault may occur after some bytes in that segment were already changed. Writes are not rolled back.

## Paging mode

`PagingMode::Unknown` is not guessed as four-level. `VaToPa()` uses a mode discovered while validating a System CR3, or a 5-level-exclusive kernel image address. Shared high-half addresses are ambiguous. `VaToPaWithMode()` lets a caller with independent evidence supply the mode explicitly. CR3 discovery validates both models against the kernel PE signature and accepts a candidate only when exactly one mode matches.

## Object state and concurrency

`Initialize()` clears old cached values before beginning and only exposes a CR3 and paging mode after successful validation. `Mmio` is move-only. The constructor owns a non-null, non-invalid `HANDLE` by default; pass `nullptr` as the fourth argument and `false` as the fifth argument to borrow one. A moved-from object has empty caches and does not own the transferred handle. Instances are not thread-safe; callers must serialize operations and status reads.
