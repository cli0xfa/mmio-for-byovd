// ============================================================================
// mmio-for-byovd  —  header-only x64 Windows kernel memory access helper.
//
// Provides kernel-mapping CR3 scanning, LA57-aware VA->PA paging-table walk, and
// cross-page-safe kernel read/write on top of a caller-supplied pair of
// physical map / unmap callbacks (the BYOVD model: you load the vulnerable
// driver, this header does the rest).
//
// Project:  https://github.com/cli0xfa/mmio-for-byovd
// License:  MIT (see the LICENSE file in this repository).
//
// Copyright (c) 2026 cli0xfa
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//
// Use of this software may be restricted by applicable law in your
// jurisdiction; obtain proper authorization before exercising it against any
// target system.
// ============================================================================

#pragma once

#if !defined(_M_X64)
#error "mmio-for-byovd requires an x64 compiler target"
#endif
#if defined(_MSVC_LANG) && _MSVC_LANG < 202002L
#error "mmio-for-byovd requires C++20 or later"
#endif

#include <windows.h>
#include <psapi.h>
#include <algorithm>
#include <cstddef>
#include <functional>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>
#include <intrin.h>
#include "mmio_paging_model.hpp"
#include "mmio_driver_enumeration_model.hpp"

// NOTE: This header-only library relies on the consumer project for linking
// psapi.lib. The pragma below is kept as a convenience so that simply
// including the header in a default-configured project works, but it can be
// suppressed by defining MMIO_NO_LIB_PRAGMA before including this header.
#ifndef MMIO_NO_LIB_PRAGMA
#pragma comment(lib, "psapi.lib")
#endif


// FnMap:  callback to map a physical page into virtual address space
//   pa     – physical address to map
//   outVa  – receives the virtual address of the mapping
//   size   – desired mapping size in bytes
//   returns true on success
// FnUnMap: callback to release a previously mapped range
//   va     – virtual address returned by FnMap
//
// FnProgress (optional, used by FindKernelCr3):
//   scannedPa – current physical address being scanned
//   returns false to request cancellation of the scan
using FnMap     = std::function<bool(uint64_t pa, uintptr_t* outVa, size_t size)>;
using FnUnMap   = std::function<void(uintptr_t va)>;
using FnProgress = std::function<bool(uint64_t scannedPa)>;
using PhysicalRange = mmio_model::PhysicalRange;
using FnGetPhysicalRanges = std::function<bool(std::vector<PhysicalRange>& outRanges)>;


// Lightweight status reporting for Initialize(). The bool return of
// Initialize() stays compatible with existing callers; the precise reason for
// a failure is available through last_status() / last_error().
enum class MmioStatus
{
	Ok,                // success
	BadCallbacks,      // null FnMap / FnUnMap supplied
	NoKernelBase,      // EnumDeviceDrivers failed to report a kernel image
	NoKernelCr3,       // physical scan did not locate a kernel-mapping CR3
	NoSystemCr3 [[deprecated("The scan does not identify the System process CR3; use NoKernelCr3")]] = NoKernelCr3,
	MappingFailed,     // FnMap declined / failed to produce a usable mapping
	TranslationFailed, // VaToPa could not translate (non-canonical / not-present / PTE read error)
	NoSeDebugPrivilege,// SeDebugPrivilege could not be enabled (required on Win11 24H2+)
	Cancelled,         // FindKernelCr3 scan was aborted via the progress callback
	InternalError,     // unexpected low-level failure (SEH-captured access violation)
	InvalidArgument,   // null buffer, zero/overflowing range, or invalid mapping result
	NotInitialized,    // operation requires successful Initialize()
	UnsupportedPagingMode, // active paging mode is unknown or ambiguous
	PhysicalRangesUnavailable, // exact physical ranges were requested but unavailable
	InvalidPhysicalRange, // supplied range is unaligned, overflows, or exceeds MAXPHYADDR
	AccessDenied,       // a Windows API denied access for another privilege or policy reason
};

struct IoResult
{
	MmioStatus status = MmioStatus::Ok;
	size_t bytes_completed = 0;
	DWORD os_error = 0;
	bool succeeded() const noexcept { return status == MmioStatus::Ok; }
};


class Mmio
{
public:
	Mmio(HANDLE h, FnMap fm, FnUnMap fu, FnGetPhysicalRanges ranges = nullptr,
	     bool ownsDeviceHandle = true)
		: hDevice_(h), ownsDeviceHandle_(ownsDeviceHandle),
		  fn_pa_map_(std::move(fm)), fn_pa_unmap_(std::move(fu)),
		  fn_get_physical_ranges_(std::move(ranges))
	{
		// Set ownsDeviceHandle=false for borrowed handles or hardware pseudo-handles.
	}

	// Non-copyable: the instance owns the device handle and cached state.
	// Move is implemented explicitly because the held HANDLE has no language
	// move semantics — a trivial/bitwise move would leave the source object
	// with the same handle and both destructors would CloseHandle it twice.
	Mmio(const Mmio&)            = delete;
	Mmio& operator=(const Mmio&) = delete;
	Mmio(Mmio&& other) noexcept
		: hDevice_(other.hDevice_)
		, ownsDeviceHandle_(other.ownsDeviceHandle_)
		, kernelbase_(other.kernelbase_)
		, kernel_cr3pa_(other.kernel_cr3pa_)
		, paging_mode_(other.paging_mode_)
		, fn_pa_map_(std::move(other.fn_pa_map_))
		, fn_pa_unmap_(std::move(other.fn_pa_unmap_))
		, fn_get_physical_ranges_(std::move(other.fn_get_physical_ranges_))
		, last_status_(other.last_status_)
		, last_error_(other.last_error_)
	{
		other.hDevice_      = INVALID_HANDLE_VALUE;
		other.ownsDeviceHandle_ = false;
		other.kernelbase_   = 0;
		other.kernel_cr3pa_ = 0;
		other.paging_mode_  = mmio_model::PagingMode::Unknown;
		other.fn_pa_map_ = nullptr;
		other.fn_pa_unmap_ = nullptr;
		other.fn_get_physical_ranges_ = nullptr;
		other.last_status_  = MmioStatus::Ok;
		other.last_error_   = 0;
	}
	Mmio& operator=(Mmio&& other) noexcept
	{
		if (this != &other) {
			if (ownsDeviceHandle_ && hDevice_ && hDevice_ != INVALID_HANDLE_VALUE)
				CloseHandle(hDevice_);
			hDevice_      = other.hDevice_;       other.hDevice_      = INVALID_HANDLE_VALUE;
			ownsDeviceHandle_ = other.ownsDeviceHandle_; other.ownsDeviceHandle_ = false;
			kernelbase_   = other.kernelbase_;     other.kernelbase_   = 0;
			kernel_cr3pa_ = other.kernel_cr3pa_;   other.kernel_cr3pa_ = 0;
			paging_mode_  = other.paging_mode_;    other.paging_mode_ = mmio_model::PagingMode::Unknown;
			fn_pa_map_   = std::move(other.fn_pa_map_);
			fn_pa_unmap_ = std::move(other.fn_pa_unmap_);
			fn_get_physical_ranges_ = std::move(other.fn_get_physical_ranges_);
			other.fn_pa_map_ = nullptr;
			other.fn_pa_unmap_ = nullptr;
			other.fn_get_physical_ranges_ = nullptr;
			last_status_ = other.last_status_;    other.last_status_ = MmioStatus::Ok;
			last_error_  = other.last_error_;     other.last_error_  = 0;
		}
		return *this;
	}

	~Mmio()
	{
		if (ownsDeviceHandle_ && hDevice_ && hDevice_ != INVALID_HANDLE_VALUE)
			CloseHandle(hDevice_);
	}

	// Initialization must succeed before ReadKernelMemory /
	// WriteKernelMemory / VaToPa (without explicit CR3).
	// Each call starts with empty caches and returns false if kernel base or
	// a kernel-mapping CR3 could not be located.
	// Precise failure reason available via last_status() / last_error().
	[[nodiscard]] bool Initialize();

	// Raw physical memory access (requires a working FnMap / FnUnMap pair).
	// Both routines require (pageOffset + size) <= 0x2000 so that a single
	// mapping window covers the range; cross-page kernel accesses should go
	// through Read/WriteKernelMemory which segment automatically.
	[[nodiscard]] bool ReadPhysicalMemory(uint64_t pa, void* buf, size_t size);
	[[nodiscard]] bool WritePhysicalMemory(uint64_t pa, const void* buf, size_t size);

	// Kernel virtual-address access. These segment the request across 4 KB
	// page boundaries, translating each segment independently, so a single
	// call safely handles arbitrarily large / cross-page buffers.
	[[nodiscard]] bool ReadKernelMemory(uint64_t va, void* buf, size_t size);
	[[nodiscard]] bool WriteKernelMemory(uint64_t va, const void* buf, size_t size);
	[[nodiscard]] IoResult ReadKernelMemoryDetailed(uint64_t va, void* buf, size_t size);
	[[nodiscard]] IoResult WriteKernelMemoryDetailed(uint64_t va, const void* buf, size_t size);
	[[nodiscard]] IoResult ReadKernelMemoryDetailed(uint64_t va, void* buf, size_t size,
	                                                uint64_t cr3pa, mmio_model::PagingMode mode);
	[[nodiscard]] IoResult WriteKernelMemoryDetailed(uint64_t va, const void* buf, size_t size,
	                                                 uint64_t cr3pa, mmio_model::PagingMode mode);

	// Translate a kernel virtual address to a physical address.
	// When cr3pa == 0 the cached kernel_cr3pa_ (set by Initialize / FindKernelCr3) is used.
	// Returns 0 on any failure (non-canonical VA, not-present entry, unmapped PTE, read error).
	uint64_t VaToPa(uint64_t va, uint64_t cr3pa = 0);
	uint64_t VaToPaWithMode(uint64_t va, uint64_t cr3pa, mmio_model::PagingMode mode);
	mmio_model::PagingMode paging_mode() const { return paging_mode_; }

	// Locate the NT kernel base address (via EnumDeviceDrivers).
	// Attempts to enable SeDebugPrivilege for this lookup; the privilege must
	// be present in the process token on Windows 11 24H2 and later.
	uint64_t GetKernelBase();

	// Scan physical memory for a page-table root that maps the kernel image.
	// This does not identify the System process's CR3: other kernel address
	// spaces can satisfy the same kernel-image translation check.
	// progress is an optional cancellation callback (return false to abort);
	// it is invoked once per scanned 2 MB window with the current physical address.
	uint64_t FindKernelCr3(FnProgress progress = nullptr);
	[[deprecated("This only finds a kernel-mapping CR3, not the System process CR3; use FindKernelCr3")]]
	uint64_t FindSystemCr3(FnProgress progress = nullptr)
	{
		return FindKernelCr3(std::move(progress));
	}

	// Cached values filled by Initialize().
	uint64_t kernel_base()  const { return kernelbase_; }
	uint64_t kernel_cr3pa() const { return kernel_cr3pa_; }
	[[deprecated("This is a kernel-mapping CR3, not necessarily the System process CR3; use kernel_cr3pa")]]
	uint64_t system_cr3pa() const { return kernel_cr3pa_; }

	// Diagnostic accessors used after Initialize() / Read* / Write* failures.
	MmioStatus   last_status() const { return last_status_; }
	DWORD        last_error()  const { return last_error_; }

private:
	// RAII scope guard around the mapping callbacks. Owns the mapping for the
	// duration of a stack scope and guarantees fn_pa_unmap_ on every exit path
	// (including C++ exceptions thrown out of the callbacks).
	struct ScopedMap
	{
		const FnUnMap* unmap = nullptr;
		uintptr_t      va   = 0;
		bool           owns = false;

		// Explicit ctor: a user-declared destructor disqualifies this struct
		// from C++20 aggregate-init, so brace-initialization requires a ctor.
		ScopedMap(const FnUnMap* u, uintptr_t v, bool o) noexcept
			: unmap(u), va(v), owns(o) {}
		ScopedMap(const ScopedMap&) = delete;
		ScopedMap& operator=(const ScopedMap&) = delete;
		~ScopedMap() noexcept
		{
			if (!owns || !unmap || !*unmap) return;
			try {
				(*unmap)(va);
			} catch (...) {
				// The unmap callback is documented as non-throwing (see the
				// callback-contract section of the README). Swallow any stray
				// exception so RAII unwinding during stack-unwinding does not
				// trigger std::terminate; the mapping is released best-effort
				// regardless.
			}
		}
	};

	// Resolves the physical-address mask (MAXPHYADDR) once and caches it.
	static uint64_t PaddrMask();
	static unsigned PaddrBits();
	bool ReadKernelMemoryImpl(uint64_t va, void* buf, size_t size, size_t* completed,
	                          uint64_t cr3pa = 0, mmio_model::PagingMode mode = mmio_model::PagingMode::Unknown);
	bool WriteKernelMemoryImpl(uint64_t va, const void* buf, size_t size, size_t* completed,
	                           uint64_t cr3pa = 0, mmio_model::PagingMode mode = mmio_model::PagingMode::Unknown);
	static bool TryMap(const FnMap& fm, uint64_t pa, uintptr_t* outVa, size_t size) noexcept
	{
		if (!outVa || !fm) return false;
		*outVa = 0;
		try { return fm(pa, outVa, size); }
		catch (...) { return false; }
	}

	// Returns true iff callbacks are usable.
	bool CallbacksValid() const { return static_cast<bool>(fn_pa_map_) && static_cast<bool>(fn_pa_unmap_); }

	// Shared 4-level/5-level canonical addresses do not identify the active
	// mode. Only an address exclusive to LA57 proves 5-level paging.
	mmio_model::PagingMode DetectPagingMode() const noexcept
	{
		if (kernelbase_ && mmio_model::IsCanonical(kernelbase_, 57) &&
		    !mmio_model::IsCanonical(kernelbase_, 48))
			return mmio_model::PagingMode::FiveLevel;
		return mmio_model::PagingMode::Unknown;
	}

	// SEH / exception-safe helpers. SehCopy is the single __try/__except leaf
	// (no C++ destructors in its frame, as required under MSVC /EHsc); the
	// SehRead* wrappers own mappings via ScopedMap and delegate the actual
	// memory read to SehCopy. Defined out-of-line below.
	static bool SehCopy(void* dst, const void* src, size_t n);
	static bool SehReadPte(uint64_t ptePa, uint64_t* out,
	                       const FnMap& fm, const FnUnMap& fu,
	                       MmioStatus* failureStatus = nullptr);
	static bool SehReadMagic(uint64_t pa, uint16_t* outMagic, uint32_t* outLfanew,
	                         const FnMap& fm, const FnUnMap& fu);
	static bool SehReadHighHalfEntry(const uint8_t* tableBase, size_t entryOff, uint64_t* out);

	// Attempt to enable SeDebugPrivilege (required by EnumDeviceDrivers on
	// Windows 11 24H2+); returns true on success. Failure is non-fatal on
	// older Windows versions where the privilege is not enforced.
	static bool EnableSeDebugPrivilege();

	// reserved for direct IOCTL usage by consumers / subclasses
	HANDLE   hDevice_      = INVALID_HANDLE_VALUE;
	bool     ownsDeviceHandle_ = true;
	uint64_t kernelbase_   = 0;
	uint64_t kernel_cr3pa_ = 0;
	mmio_model::PagingMode paging_mode_ = mmio_model::PagingMode::Unknown;
	FnMap    fn_pa_map_;
	FnUnMap  fn_pa_unmap_;
	FnGetPhysicalRanges fn_get_physical_ranges_;
	// diagnostics: set on Initialize()/Read*/Write* failure paths.
	mutable MmioStatus last_status_ = MmioStatus::Ok;
	mutable DWORD      last_error_  = 0;
};


// ---------------------------------------------------------------------------
// Internal SEH leaf helpers
// ---------------------------------------------------------------------------

// SEH-protected memcpy leaf. This is the ONLY function in the library that
// uses __try/__except. Its frame contains no C++ objects with destructors
// (only scalars/pointers), which is a hard requirement for __try under MSVC
// /EHsc (see compiler error C2712). All callers own any mappings via
// ScopedMap, so a fault here simply yields false and the caller unmaps.
inline bool Mmio::SehCopy(void* dst, const void* src, size_t n)
{
	bool ok = true;
	__try {
		memcpy(dst, src, n);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ok = false;
	}
	return ok;
}

// Reads a single 8-byte PTE from the given physical address. The mapping is
// owned by a ScopedMap guard (exception-safe); the read itself goes through
// the SehCopy leaf so an access violation is reported, never propagated.
inline bool Mmio::SehReadPte(uint64_t ptePa, uint64_t* out,
                             const FnMap& fm, const FnUnMap& fu,
                             MmioStatus* failureStatus)
{
	uintptr_t mapped = 0;
	if (!TryMap(fm, ptePa & ~0xFFFull, &mapped, 0x1000)) {
		if (failureStatus) *failureStatus = MmioStatus::MappingFailed;
		return false;
	}

	ScopedMap guard{ &fu, mapped, true };
	const uintptr_t offset = static_cast<uintptr_t>(ptePa & 0xFFFull);
	if (mapped == 0 || mapped > UINTPTR_MAX - 0x1000u ||
	    mapped > UINTPTR_MAX - offset - sizeof(uint64_t)) {
		if (failureStatus) *failureStatus = MmioStatus::InvalidArgument;
		return false;
	}
	if (!SehCopy(out, reinterpret_cast<const void*>(mapped + offset), sizeof(uint64_t))) {
		if (failureStatus) *failureStatus = MmioStatus::InternalError;
		return false;
	}
	if (failureStatus) *failureStatus = MmioStatus::Ok;
	return true;
}

// Reads the MZ magic and e_lfanew from the first page of a kernel image.
// The mapping is ScopedMap-owned; reads go through SehCopy so any access
// violation is reported as a failure rather than tearing down the caller.
inline bool Mmio::SehReadMagic(uint64_t pa, uint16_t* outMagic, uint32_t* outLfanew,
                               const FnMap& fm, const FnUnMap& fu)
{
	// The DOS header fields we need (e_magic@0, e_lfanew@0x3C) may straddle a
	// page boundary when `pa` is not page-aligned (e.g. pa & 0xFFF near 0xFC0
	// puts base + 0x3C past the end of a single 4 KB mapping). Map a 2-page
	// window so the read stays covered for any in-page offset; the SEH leaf
	// still reports any fault as a failure. `pa` is page-aligned in practice
	// (the kernel image base), but this keeps the helper safe for any input.
	uintptr_t mapped = 0;
	if (!TryMap(fm, pa & ~0xFFFull, &mapped, 0x2000)) return false;

	ScopedMap guard{ &fu, mapped, true };
	const uintptr_t offset = static_cast<uintptr_t>(pa & 0xFFFull);
	if (mapped == 0 || mapped > UINTPTR_MAX - 0x2000u ||
	    mapped > UINTPTR_MAX - offset - 0x40u) return false;
	const uint8_t* base = reinterpret_cast<const uint8_t*>(mapped + (pa & 0xFFFull));
	if (!SehCopy(outMagic, base, sizeof(uint16_t)))
		return false;
	// e_lfanew is at offset 0x3C of the DOS header.
	return SehCopy(outLfanew, base + 0x3C, sizeof(uint32_t));
}

// Reads one 8-byte entry of the candidate top-level paging table (PML4 under
// 4-level paging, PML5 under 5-level paging). `tableBase` is already mapped by
// the caller; `entryOff` is derived from the candidate kernel VA's top-level
// index. Pure read helper — the SEH leaf reports any fault as a failure.
inline bool Mmio::SehReadHighHalfEntry(const uint8_t* tableBase, size_t entryOff, uint64_t* out)
{
	const uintptr_t base = reinterpret_cast<uintptr_t>(tableBase);
	if (!tableBase || !out || entryOff > 0xFF8u || base > UINTPTR_MAX - entryOff - sizeof(uint64_t))
		return false;
	return SehCopy(out, tableBase + entryOff, sizeof(uint64_t));
}


// ---------------------------------------------------------------------------
// Public API implementation
// ---------------------------------------------------------------------------

inline uint64_t Mmio::PaddrMask()
{
	// CPUID leaf 0x80000008:EAX[7:0] = MAXPHYADDR (typically 48 or 52).
	// Computed once and cached; MAXPHYADDR is constant for the lifetime of
	// the process, so a thread-safe function-local static suffices.
	static const uint64_t mask = []() -> uint64_t {
		int cpuInfo[4] = {};

		// Validate that the extended CPUID range exists before querying
		// 0x80000008. On legacy/filtered CPUs a CPUID(0x80000000) query may
		// silently echo the last standard leaf instead of returning the max
		// extended leaf, yielding garbage (see how Linux KVM sanitizes
		// CPUID(0x80000000)). AMD64 long mode guarantees the leaf, but a
		// hypervisor — common in BYOVD target VMs — may hide it.
		__cpuidex(cpuInfo, static_cast<int>(0x80000000), 0);
		const unsigned int maxExtLeaf = static_cast<unsigned int>(cpuInfo[0]);
		if ((maxExtLeaf & 0xFFFF0000u) != 0x80000000u ||
		    maxExtLeaf < 0x80000008u) {
			// Extended leaves unavailable — fall back to 52 bits (the
			// architectural maximum PA width). PTE reserved bits above
			// MAXPHYADDR are zero by hardware/OS convention, so a wider mask
			// still yields correct PTE-derived physical addresses instead of
			// truncating real PAs (a 36-bit fallback would clip memory beyond
			// 64 GB, present on most modern machines).
			return ((1ull << 52) - 1ull) & ~0xFFFull;
		}

		__cpuidex(cpuInfo, static_cast<int>(0x80000008), 0);
		unsigned int maxPaBits = static_cast<unsigned int>(cpuInfo[0] & 0xFFu);
		if (maxPaBits == 0 || maxPaBits >= 64) maxPaBits = 52; // defensive default
		return ((1ull << maxPaBits) - 1ull) & ~0xFFFull;
	}();
	return mask;
}

inline unsigned Mmio::PaddrBits()
{
	const uint64_t mask = PaddrMask();
	unsigned bits = 12;
	while (bits < 52 && (mask & (1ull << bits)) != 0) ++bits;
	return bits;
}

inline bool Mmio::Initialize()
{
	// Initialization is transactional: callers never observe stale cached
	// addresses from a previous attempt after a later attempt fails.
	kernelbase_   = 0;
	kernel_cr3pa_ = 0;
	paging_mode_  = mmio_model::PagingMode::Unknown;
	last_status_ = MmioStatus::Ok;
	last_error_  = 0;

	if (!CallbacksValid()) {
		last_status_ = MmioStatus::BadCallbacks;
		return false;
	}

	kernelbase_ = GetKernelBase();
	if (!kernelbase_) {
		if (last_error_ == ERROR_PRIVILEGE_NOT_HELD)
			last_status_ = MmioStatus::NoSeDebugPrivilege;
		else if (last_error_ == ERROR_ACCESS_DENIED)
			last_status_ = MmioStatus::AccessDenied;
		else
			last_status_ = MmioStatus::NoKernelBase;
		return false;
	}

	kernel_cr3pa_ = FindKernelCr3();
	if (!kernel_cr3pa_) {
		if (last_status_ == MmioStatus::Ok) last_status_ = MmioStatus::NoKernelCr3;
		return false;
	}

	last_status_ = MmioStatus::Ok;
	return true;
}

inline bool Mmio::ReadPhysicalMemory(uint64_t pa, void* buf, size_t size)
{
	last_error_  = 0;
	last_status_ = MmioStatus::Ok;

	if (size == 0 || buf == nullptr || size > UINT64_MAX - pa) {
		last_status_ = MmioStatus::InvalidArgument;
		return false;
	}
	if (!CallbacksValid()) {
		last_status_ = MmioStatus::BadCallbacks;
		return false;
	}
	// Bound `size` on its own before forming pageOffset + size. A caller
	// passing size ≈ SIZE_MAX would otherwise wrap requiredSize to a small
	// value and bypass the 0x2000 limit below; the SEH leaf would still catch
	// the fault, but the documented "single mapping window covers the range"
	// invariant (pageOffset + size ≤ 0x2000) must hold arithmetically, not via
	// fault tolerance.
	if (size > 0x2000)            { last_status_ = MmioStatus::InvalidArgument; return false; }

	const uintptr_t pageOffset   = static_cast<uintptr_t>(pa & 0xFFFull);
	const size_t    requiredSize = pageOffset + size;   // size ≤ 0x2000 ⇒ no wrap
	// A single mapping window covers at most one page boundary crossing, i.e.
	// pageOffset + size must not exceed 0x2000. Larger or multi-page requests
	// must be segmented by the caller (e.g. ReadKernelMemory).
	if (requiredSize > 0x2000) {
		last_status_ = MmioStatus::InvalidArgument;
		return false;
	}
	const size_t mapSize = (requiredSize > 0x1000) ? 0x2000 : 0x1000;
	const uint64_t alignedPa = pa & ~0xFFFull;

	uintptr_t mapped = 0;
	if (!TryMap(fn_pa_map_, alignedPa, &mapped, mapSize)) {
		last_status_ = MmioStatus::MappingFailed;
		return false;
	}

	ScopedMap guard{ &fn_pa_unmap_, mapped, true };
	if (mapped == 0 || mapped > UINTPTR_MAX - mapSize) {
		last_status_ = MmioStatus::InvalidArgument;
		return false;
	}

	const bool ok = SehCopy(buf, reinterpret_cast<void*>(mapped + pageOffset), size);
	if (!ok)
		last_status_ = MmioStatus::InternalError;
	return ok;
}

inline bool Mmio::WritePhysicalMemory(uint64_t pa, const void* buf, size_t size)
{
	last_error_  = 0;
	last_status_ = MmioStatus::Ok;

	if (size == 0 || buf == nullptr || size > UINT64_MAX - pa) {
		last_status_ = MmioStatus::InvalidArgument;
		return false;
	}
	if (!CallbacksValid()) {
		last_status_ = MmioStatus::BadCallbacks;
		return false;
	}
	// Bound size on its own first (see ReadPhysicalMemory for the full
	// rationale): a near-SIZE_MAX request must not wrap requiredSize past the
	// 0x2000 limit — the single-window invariant holds arithmetically, not
	// only via the SEH leaf's fault tolerance.
	if (size > 0x2000)            { last_status_ = MmioStatus::InvalidArgument; return false; }

	const uintptr_t pageOffset   = static_cast<uintptr_t>(pa & 0xFFFull);
	const size_t    requiredSize = pageOffset + size;   // size ≤ 0x2000 ⇒ no wrap
	if (requiredSize > 0x2000) {
		last_status_ = MmioStatus::InvalidArgument;
		return false;
	}
	const size_t mapSize = (requiredSize > 0x1000) ? 0x2000 : 0x1000;
	const uint64_t alignedPa = pa & ~0xFFFull;

	uintptr_t mapped = 0;
	if (!TryMap(fn_pa_map_, alignedPa, &mapped, mapSize)) {
		last_status_ = MmioStatus::MappingFailed;
		return false;
	}

	ScopedMap guard{ &fn_pa_unmap_, mapped, true };
	if (mapped == 0 || mapped > UINTPTR_MAX - mapSize) {
		last_status_ = MmioStatus::InvalidArgument;
		return false;
	}

	const bool ok = SehCopy(reinterpret_cast<void*>(mapped + pageOffset), buf, size);
	if (!ok)
		last_status_ = MmioStatus::InternalError;
	return ok;
}

inline bool Mmio::ReadKernelMemory(uint64_t va, void* buf, size_t size)
{
	return ReadKernelMemoryImpl(va, buf, size, nullptr);
}

inline IoResult Mmio::ReadKernelMemoryDetailed(uint64_t va, void* buf, size_t size)
{
	size_t completed = 0;
	const bool ok = ReadKernelMemoryImpl(va, buf, size, &completed);
	return {ok ? MmioStatus::Ok : last_status_, completed, last_error_};
}

inline IoResult Mmio::ReadKernelMemoryDetailed(uint64_t va, void* buf, size_t size,
                                               uint64_t cr3pa, mmio_model::PagingMode mode)
{
	size_t completed = 0;
	const bool ok = ReadKernelMemoryImpl(va, buf, size, &completed, cr3pa, mode);
	return {ok ? MmioStatus::Ok : last_status_, completed, last_error_};
}

inline bool Mmio::ReadKernelMemoryImpl(uint64_t va, void* buf, size_t size, size_t* completed,
                                       uint64_t cr3pa, mmio_model::PagingMode mode)
{
	last_error_  = 0;
	last_status_ = MmioStatus::Ok;
	if (completed) *completed = 0;

	if (size == 0 || size > UINT64_MAX - va || buf == nullptr) {
		last_status_ = MmioStatus::InvalidArgument;
		return false;
	}
	if (!CallbacksValid()) {
		last_status_ = MmioStatus::BadCallbacks;
		return false;
	}
	if (!cr3pa && !kernel_cr3pa_) {
		last_status_ = MmioStatus::NotInitialized;
		return false;
	}

	uint8_t* out = static_cast<uint8_t*>(buf);
	size_t    remaining = size;
	uint64_t  cur       = va;

	while (remaining > 0) {
		const size_t inPage = 0x1000 - static_cast<size_t>(cur & 0xFFFull);
		const size_t seg    = (remaining < inPage) ? remaining : inPage;

		const uint64_t pa = (mode == mmio_model::PagingMode::Unknown)
			? VaToPa(cur, cr3pa) : VaToPaWithMode(cur, cr3pa, mode);
		if (!pa) return false;   // VaToPa() already set last_status_ = TranslationFailed
		if (!ReadPhysicalMemory(pa, out, seg)) return false;  // status already set

		out       += seg;
		cur       += seg;
		remaining -= seg;
		if (completed) *completed += seg;
	}
	return true;
}

inline bool Mmio::WriteKernelMemory(uint64_t va, const void* buf, size_t size)
{
	return WriteKernelMemoryImpl(va, buf, size, nullptr);
}

inline IoResult Mmio::WriteKernelMemoryDetailed(uint64_t va, const void* buf, size_t size)
{
	size_t completed = 0;
	const bool ok = WriteKernelMemoryImpl(va, buf, size, &completed);
	return {ok ? MmioStatus::Ok : last_status_, completed, last_error_};
}

inline IoResult Mmio::WriteKernelMemoryDetailed(uint64_t va, const void* buf, size_t size,
                                                uint64_t cr3pa, mmio_model::PagingMode mode)
{
	size_t completed = 0;
	const bool ok = WriteKernelMemoryImpl(va, buf, size, &completed, cr3pa, mode);
	return {ok ? MmioStatus::Ok : last_status_, completed, last_error_};
}

inline bool Mmio::WriteKernelMemoryImpl(uint64_t va, const void* buf, size_t size, size_t* completed,
                                        uint64_t cr3pa, mmio_model::PagingMode mode)
{
	last_error_  = 0;
	last_status_ = MmioStatus::Ok;
	if (completed) *completed = 0;

	if (size == 0 || size > UINT64_MAX - va || buf == nullptr) {
		last_status_ = MmioStatus::InvalidArgument;
		return false;
	}
	if (!CallbacksValid()) {
		last_status_ = MmioStatus::BadCallbacks;
		return false;
	}
	if (!cr3pa && !kernel_cr3pa_) {
		last_status_ = MmioStatus::NotInitialized;
		return false;
	}

	const uint8_t* in = static_cast<const uint8_t*>(buf);
	size_t    remaining = size;
	uint64_t  cur       = va;

	while (remaining > 0) {
		const size_t inPage = 0x1000 - static_cast<size_t>(cur & 0xFFFull);
		const size_t seg    = (remaining < inPage) ? remaining : inPage;

		const uint64_t pa = (mode == mmio_model::PagingMode::Unknown)
			? VaToPa(cur, cr3pa) : VaToPaWithMode(cur, cr3pa, mode);
		if (!pa) return false;   // VaToPa() already set last_status_ = TranslationFailed
		if (!WritePhysicalMemory(pa, in, seg)) return false;  // status already set

		in        += seg;
		cur       += seg;
		remaining -= seg;
		if (completed) *completed += seg;
	}
	return true;
}

inline uint64_t Mmio::VaToPa(uint64_t va, uint64_t cr3pa)
{
	const auto mode = paging_mode_ != mmio_model::PagingMode::Unknown
		? paging_mode_ : DetectPagingMode();
	return VaToPaWithMode(va, cr3pa, mode);
}

inline uint64_t Mmio::VaToPaWithMode(uint64_t va, uint64_t cr3pa,
                                    mmio_model::PagingMode mode)
{
	last_error_  = 0;
	last_status_ = MmioStatus::Ok;
	if (!cr3pa) cr3pa = kernel_cr3pa_;
	if (!cr3pa) {
		last_status_ = MmioStatus::NotInitialized;
		return 0;
	}
	if (!CallbacksValid()) {
		last_status_ = MmioStatus::BadCallbacks;
		return 0;
	}
	if (mode == mmio_model::PagingMode::Unknown) {
		last_status_ = MmioStatus::UnsupportedPagingMode;
		return 0;
	}

	MmioStatus readFailureStatus = MmioStatus::TranslationFailed;
	const auto result = mmio_model::WalkPageTables(va, cr3pa, PaddrBits(), mode,
		[this, &readFailureStatus](uint64_t ptePa, uint64_t& value) {
			return SehReadPte(ptePa, &value, fn_pa_map_, fn_pa_unmap_, &readFailureStatus);
		});
	if (!result) {
		if (result.error == mmio_model::WalkError::UnsupportedMode)
			last_status_ = MmioStatus::UnsupportedPagingMode;
		else if (result.error == mmio_model::WalkError::ReadFailure)
			last_status_ = readFailureStatus;
		else
			last_status_ = MmioStatus::TranslationFailed;
		return 0;
	}
	if (result.physical_address == 0) {
		// The legacy API uses zero as its failure sentinel, so a valid mapping
		// of physical page zero cannot be represented to callers.
		last_status_ = MmioStatus::TranslationFailed;
		return 0;
	}
	return result.physical_address;
}

// Best-effort enablement of SeDebugPrivilege. Required by EnumDeviceDrivers
// on Windows 11 24H2+; on older Windows the privilege is not enforced so
// failure here is non-fatal. Returns true if the privilege was enabled.
inline bool Mmio::EnableSeDebugPrivilege()
{
	HANDLE hToken = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(),
	                      TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return false;

	TOKEN_PRIVILEGES tp = {};
	tp.PrivilegeCount = 1;
	if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege",
	                           &tp.Privileges[0].Luid)) {
		CloseHandle(hToken);
		return false;
	}
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	SetLastError(ERROR_SUCCESS);
	BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp,
	                                    sizeof(tp), nullptr, nullptr);
	DWORD err = GetLastError();
	CloseHandle(hToken);
	return result && err == ERROR_SUCCESS;
}

inline uint64_t Mmio::GetKernelBase()
{
	last_error_  = 0;
	last_status_ = MmioStatus::Ok;
	// EnumDeviceDrivers returns NULL image bases on Windows 11 24H2+ unless
	// SeDebugPrivilege is enabled. Keep this public method self-contained;
	// failure to enable remains non-fatal on older systems where it is not needed.
	EnableSeDebugPrivilege();

	auto failWithError = [this](DWORD error) -> uint64_t {
		last_error_ = error;
		if (error == ERROR_PRIVILEGE_NOT_HELD)
			last_status_ = MmioStatus::NoSeDebugPrivilege;
		else if (error == ERROR_ACCESS_DENIED)
			last_status_ = MmioStatus::AccessDenied;
		else
			last_status_ = MmioStatus::NoKernelBase;
		return 0;
	};

	auto enumerateDrivers = [](LPVOID* entries, size_t capacityBytes) {
		if (capacityBytes > MAXDWORD)
			return mmio_model::EnumerationCall{
				mmio_model::EnumerationCallStatus::Failure, 0, ERROR_ARITHMETIC_OVERFLOW};
		DWORD reportedBytes = 0;
		const BOOL success = EnumDeviceDrivers(entries, static_cast<DWORD>(capacityBytes),
		                                       &reportedBytes);
		const DWORD error = success ? ERROR_SUCCESS : GetLastError();
		const auto status = success
			? mmio_model::EnumerationCallStatus::Success
			: error == ERROR_INSUFFICIENT_BUFFER
				? mmio_model::EnumerationCallStatus::InsufficientBuffer
				: mmio_model::EnumerationCallStatus::Failure;
		return mmio_model::EnumerationCall{status, static_cast<size_t>(reportedBytes), error};
	};
	const auto enumeration = mmio_model::CollectEnumeration<LPVOID>(enumerateDrivers);
	if (!enumeration) {
		DWORD error = enumeration.os_error;
		switch (enumeration.error) {
		case mmio_model::EnumerationError::None:
			break;
		case mmio_model::EnumerationError::ApiFailure:
			if (error == ERROR_SUCCESS) error = ERROR_GEN_FAILURE;
			break;
		case mmio_model::EnumerationError::Empty:
			error = ERROR_NOT_FOUND;
			break;
		case mmio_model::EnumerationError::InvalidLength:
			error = ERROR_INVALID_DATA;
			break;
		case mmio_model::EnumerationError::Unstable:
			if (error == ERROR_SUCCESS) error = ERROR_INSUFFICIENT_BUFFER;
			break;
		case mmio_model::EnumerationError::AllocationFailure:
			error = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
		return failWithError(error);
	}
	const auto& drivers = enumeration.entries;
	const bool anyBase = std::any_of(drivers.begin(), drivers.end(),
	                                 [](LPVOID base) { return base != nullptr; });
	// On Windows 11 24H2+, EnumDeviceDrivers can return TRUE while filling
	// every entry with NULL when SeDebugPrivilege is unavailable.
	if (!anyBase) return failWithError(ERROR_PRIVILEGE_NOT_HELD);

	// Identify the NT kernel by its base name rather than assuming the first
	// enumerated module is the kernel. Accept exactly one recognized image.
	static const wchar_t* const kKernelNames[] = {
		L"ntoskrnl.exe", L"ntkrnlmp.exe",
		L"ntoskrnlpa.exe", L"ntkrpamp.exe"
	};
	wchar_t nameBuf[64] = {};
	std::vector<LPVOID> kernelCandidates;
	try {
		kernelCandidates.reserve(drivers.size());
		for (LPVOID drvBase : drivers) {
			if (!drvBase) continue;
			if (GetDeviceDriverBaseNameW(drvBase, nameBuf,
			                             static_cast<DWORD>(sizeof(nameBuf) / sizeof(nameBuf[0]))) == 0)
				continue;
			for (const wchar_t* k : kKernelNames) {
				if (lstrcmpiW(nameBuf, k) == 0) {
					kernelCandidates.push_back(drvBase);
					break;
				}
			}
		}
	} catch (...) {
		return failWithError(ERROR_NOT_ENOUGH_MEMORY);
	}
	const auto selection = mmio_model::SelectUniqueMatch(kernelCandidates,
		[](size_t) { return true; });
	if (selection.selection == mmio_model::MatchSelection::None)
		return failWithError(ERROR_NOT_FOUND);
	if (selection.selection == mmio_model::MatchSelection::Ambiguous)
		return failWithError(ERROR_INVALID_DATA);

	last_status_ = MmioStatus::Ok;
	last_error_ = 0;
	return reinterpret_cast<uint64_t>(kernelCandidates[selection.index]);
}

inline uint64_t Mmio::FindKernelCr3(FnProgress progress)
{
	last_error_  = 0;
	last_status_ = MmioStatus::Ok;
	if (!CallbacksValid()) {
		last_status_ = MmioStatus::BadCallbacks;
		return 0;
	}
	if (!kernelbase_) {
		last_status_ = MmioStatus::NoKernelBase;
		return 0;
	}

	std::vector<PhysicalRange> ranges;
	if (fn_get_physical_ranges_) {
		try {
			if (!fn_get_physical_ranges_(ranges)) {
				last_status_ = MmioStatus::PhysicalRangesUnavailable;
				return 0;
			}
		} catch (...) {
			last_status_ = MmioStatus::InternalError;
			return 0;
		}
	} else {
		// Backward-compatible estimate. Installed capacity is not a physical
		// address ceiling; callers with memory holes/remapping should provide
		// FnGetPhysicalRanges to enumerate the actual ranges.
		ULONGLONG totalMemoryKiB = 0;
		uint64_t estimatedSpan = 0x2000000000ull; // 128 GB fallback
		if (GetPhysicallyInstalledSystemMemory(&totalMemoryKiB) && totalMemoryKiB > 0) {
			estimatedSpan = totalMemoryKiB <= UINT64_MAX / 1024
				? totalMemoryKiB * 1024 : 0x2000000000ull;
		}
		estimatedSpan &= ~uint64_t{0xFFF};
		if (estimatedSpan) ranges.push_back({0, estimatedSpan});
	}

	const auto rangeError = mmio_model::NormalizePhysicalRanges(ranges);
	if (rangeError == mmio_model::RangeError::Empty) {
		last_status_ = MmioStatus::PhysicalRangesUnavailable;
		return 0;
	}
	if (rangeError != mmio_model::RangeError::None) {
		last_status_ = MmioStatus::InvalidPhysicalRange;
		return 0;
	}
	for (const auto& range : ranges) {
		if (!mmio_model::IsPhysicalRangeSupported(range.base, range.length, PaddrBits())) {
			last_status_ = MmioStatus::InvalidPhysicalRange;
			return 0;
		}
	}

	constexpr uint64_t chunkSize = 0x200000; // 2 MB
	constexpr uint64_t pageSize  = 0x1000;   // 4 KB
	bool sawAmbiguousMode = false;
	bool anyMapping = false;
	bool sawNullMapping = false;
	bool sawInvalidMapAddress = false;

	for (const auto& range : ranges) {
		const uint64_t rangeEnd = range.base + range.length;
		for (uint64_t pa = range.base; pa < rangeEnd; ) {
			const uint64_t windowSize = (rangeEnd - pa < chunkSize) ? (rangeEnd - pa) : chunkSize;
			if (progress) {
				try {
					if (!progress(pa)) {
						last_status_ = MmioStatus::Cancelled;
						return 0;
					}
				} catch (...) {
					last_status_ = MmioStatus::InternalError;
					return 0;
				}
			}

			uintptr_t chunkVa = 0;
			const uint8_t* chunkBuf = nullptr;
			bool chunkMapped = TryMap(fn_pa_map_, pa, &chunkVa, static_cast<size_t>(windowSize));
			if (chunkMapped) anyMapping = true;
			ScopedMap chunkGuard{ &fn_pa_unmap_, chunkVa, chunkMapped };
			if (chunkMapped && chunkVa != 0 && chunkVa <= UINTPTR_MAX - windowSize) {
				chunkBuf = reinterpret_cast<const uint8_t*>(chunkVa);
			} else {
				if (chunkMapped && chunkVa == 0) sawNullMapping = true;
				else if (chunkMapped) sawInvalidMapAddress = true;
				chunkMapped = false;
			}

			bool found = false;
			uint64_t resultCr3 = 0;
			mmio_model::PagingMode resultMode = mmio_model::PagingMode::Unknown;
			for (uint64_t offset = 0; offset < windowSize; offset += pageSize) {
				const uint64_t cr3Candidate = pa + offset;
				const uint8_t* pageBase = nullptr;
				uintptr_t pageVa = 0;
				bool pageMapped = false;
				if (chunkMapped) {
					pageBase = chunkBuf + static_cast<size_t>(offset);
				} else {
					pageMapped = TryMap(fn_pa_map_, cr3Candidate, &pageVa, pageSize);
					if (!pageMapped) continue;
					anyMapping = true;
					if (pageVa == 0) sawNullMapping = true;
					else if (pageVa > UINTPTR_MAX - pageSize) sawInvalidMapAddress = true;
					else pageBase = reinterpret_cast<const uint8_t*>(pageVa);
				}
				ScopedMap pageGuard{ &fn_pa_unmap_, pageVa, pageMapped };
				if (!pageBase) { sawNullMapping = true; continue; }

				auto validateForMode = [&](mmio_model::PagingMode mode) -> bool {
					const size_t topEntryOffset =
						static_cast<size_t>(mmio_model::TopLevelIndex(kernelbase_, mode)) * 8;
					uint64_t topEntry = 0;
					if (!SehReadHighHalfEntry(pageBase, topEntryOffset, &topEntry) || !(topEntry & 1))
						return false;

					const uint64_t kernelPa = VaToPaWithMode(kernelbase_, cr3Candidate, mode);
					if (!kernelPa) return false;
					uint16_t magic = 0;
					uint32_t lfanew = 0;
					if (!SehReadMagic(kernelPa, &magic, &lfanew, fn_pa_map_, fn_pa_unmap_) ||
					    magic != 0x5A4D || lfanew == 0 || lfanew > 0x400)
						return false;
					if (!mmio_model::IsValidRange(kernelbase_, static_cast<uint64_t>(lfanew) + sizeof(uint32_t)))
						return false;

					const uint64_t peHeaderPa = VaToPaWithMode(kernelbase_ + lfanew, cr3Candidate, mode);
					if (!peHeaderPa) return false;
					uint32_t peSignature = 0;
					return ReadPhysicalMemory(peHeaderPa, &peSignature, sizeof(peSignature)) &&
					       peSignature == 0x00004550;
				};

				const bool valid4 = validateForMode(mmio_model::PagingMode::FourLevel);
				const bool valid5 = validateForMode(mmio_model::PagingMode::FiveLevel);
				if (valid4 && valid5) {
					sawAmbiguousMode = true;
					continue;
				}
				if (!valid4 && !valid5) continue;
				resultCr3 = cr3Candidate;
				resultMode = valid4 ? mmio_model::PagingMode::FourLevel
				                    : mmio_model::PagingMode::FiveLevel;
				found = true;
				break;
			}

			if (found) {
				kernel_cr3pa_ = resultCr3;
				paging_mode_ = resultMode;
				last_status_ = MmioStatus::Ok;
				return resultCr3;
			}
			if (rangeEnd - pa <= chunkSize) break;
			pa += chunkSize;
		}
	}

	if (sawAmbiguousMode) last_status_ = MmioStatus::UnsupportedPagingMode;
	else if (sawNullMapping || sawInvalidMapAddress) last_status_ = MmioStatus::InvalidArgument;
	else if (!anyMapping) last_status_ = MmioStatus::MappingFailed;
	else last_status_ = MmioStatus::NoKernelCr3;
	return 0;
}
