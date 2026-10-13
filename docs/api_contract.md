# API contract

## Mapping callbacks

`FnMap` receives a page-aligned physical base, a pointer for the returned user virtual address, and a nonzero length. It returns `true` only when the mapping is live and must then provide a nonzero address. A `true` result transfers one cleanup obligation to `Mmio`; `FnUnMap` is called exactly once on every exit path. A `false` result must not leave a live mapping. Callbacks should not throw and must support nested calls. `FnUnMap` exceptions are swallowed because it runs in a destructor; cleanup is best effort in that case.

`FnGetPhysicalRanges` is optional for source compatibility. When supplied, it must return the physical address ranges that the mapping backend is allowed to map. Every base and length must be 4 KB aligned, nonzero, fit within CPUID `MAXPHYADDR`, and form a non-overflowing half-open interval. The library sorts and merges overlapping or adjacent ranges before scanning. Without the provider, the legacy installed-capacity estimate is used and can miss memory above holes or remapped ranges.

## Memory operations

All read and write methods reject zero length, null buffers, and overflowing ranges with `InvalidArgument` before invoking `FnMap`. Physical reads and writes accept at most one two-page window; kernel operations split work at 4 KB boundaries. The bool methods and three-argument detailed methods use the cached System CR3 and require successful `Initialize()`. The five-argument detailed overloads can run without cached initialization when given a nonzero CR3 and an explicit paging mode.

The `bool` result reports whether the whole request completed. If a multi-page operation fails part way through, prior segments remain completed and are not rolled back. `ReadKernelMemoryDetailed` and `WriteKernelMemoryDetailed` also report the bytes in fully completed page segments. A fault part way through the current segment is not counted as completed.

## Paging mode

`PagingMode::Unknown` is not guessed as four-level. `VaToPa()` uses a mode discovered while validating a System CR3, or a 5-level-exclusive kernel image address. Shared high-half addresses are ambiguous. `VaToPaWithMode()` lets a caller with independent evidence supply the mode explicitly. CR3 discovery validates both models against the kernel PE signature and accepts a candidate only when exactly one mode matches.

## Object state and concurrency

`Initialize()` clears old cached values before beginning and only exposes a CR3 and paging mode after successful validation. `Mmio` is move-only. The constructor owns a non-null, non-invalid `HANDLE` by default; pass `nullptr` as the fourth argument and `false` as the fifth argument to borrow one. A moved-from object has empty caches and does not own the transferred handle. Instances are not thread-safe; callers must serialize operations and status reads.
