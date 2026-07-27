#pragma once

#include <windows.h>
#include <psapi.h>
#include <functional>
#include <cstdint>
#include <vector>
#include <intrin.h>

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
// FnProgress (optional, used by FindSystemCr3):
//   scannedPa – current physical address being scanned
//   returns false to request cancellation of the scan
using FnMap     = std::function<bool(uint64_t pa, uintptr_t* outVa, size_t size)>;
using FnUnMap   = std::function<void(uintptr_t va)>;
using FnProgress = std::function<bool(uint64_t scannedPa)>;


// Lightweight status reporting for Initialize(). The bool return of
// Initialize() stays compatible with existing callers; the precise reason for
// a failure is available through last_status() / last_error().
enum class MmioStatus
{
	Ok,                // success
	BadCallbacks,      // null FnMap / FnUnMap supplied
	NoKernelBase,      // EnumDeviceDrivers failed to report a kernel image
	NoSystemCr3,       // physical scan did not locate the System CR3
	MappingFailed,     // FnMap declined / failed to produce a usable mapping
	TranslationFailed, // VaToPa could not translate (non-canonical / not-present / PTE read error)
	NoSeDebugPrivilege,// SeDebugPrivilege could not be enabled (required on Win11 24H2+)
	InternalError,     // unexpected low-level failure (SEH-captured AV / bad arguments)
};


class Mmio
{
public:
	Mmio(HANDLE h, FnMap fm, FnUnMap fu)
		: hDevice_(h), fn_pa_map_(std::move(fm)), fn_pa_unmap_(std::move(fu))
	{
		// A hardware pseudo-handle (e.g. from a parked mapping driver) may be
		// passed; we only own/close a real handle. NULL is treated as "none".
	}

	// Non-copyable: the instance owns the device handle and cached state.
	// Move is implemented explicitly because the held HANDLE has no language
	// move semantics — a trivial/bitwise move would leave the source object
	// with the same handle and both destructors would CloseHandle it twice.
	Mmio(const Mmio&)            = delete;
	Mmio& operator=(const Mmio&) = delete;
	Mmio(Mmio&& other) noexcept
		: hDevice_(other.hDevice_)
		, kernelbase_(other.kernelbase_)
		, system_cr3pa_(other.system_cr3pa_)
		, fn_pa_map_(std::move(other.fn_pa_map_))
		, fn_pa_unmap_(std::move(other.fn_pa_unmap_))
		, last_status_(other.last_status_)
		, last_error_(other.last_error_)
	{
		other.hDevice_      = INVALID_HANDLE_VALUE;
		other.kernelbase_   = 0;
		other.system_cr3pa_ = 0;
	}
	Mmio& operator=(Mmio&& other) noexcept
	{
		if (this != &other) {
			if (hDevice_ && hDevice_ != INVALID_HANDLE_VALUE)
				CloseHandle(hDevice_);
			hDevice_      = other.hDevice_;       other.hDevice_      = INVALID_HANDLE_VALUE;
			kernelbase_   = other.kernelbase_;     other.kernelbase_   = 0;
			system_cr3pa_ = other.system_cr3pa_;   other.system_cr3pa_ = 0;
			fn_pa_map_   = std::move(other.fn_pa_map_);
			fn_pa_unmap_ = std::move(other.fn_pa_unmap_);
			last_status_ = other.last_status_;
			last_error_  = other.last_error_;
		}
		return *this;
	}

	~Mmio()
	{
		if (hDevice_ && hDevice_ != INVALID_HANDLE_VALUE)
			CloseHandle(hDevice_);
	}

	// One-shot initialization – must be called before ReadKernelMemory /
	// WriteKernelMemory / VaToPa (without explicit CR3).
	// Returns false if kernel base or system CR3 could not be located.
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

	// Translate a kernel virtual address to a physical address.
	// When cr3pa == 0 the cached system_cr3pa_ (set by Initialize / FindSystemCr3) is used.
	// Returns 0 on any failure (non-canonical VA, not-present entry, unmapped PTE, read error).
	uint64_t VaToPa(uint64_t va, uint64_t cr3pa = 0);

	// Locate the NT kernel base address (via EnumDeviceDrivers).
	uint64_t GetKernelBase();

	// Scan physical memory for the System process CR3 value.
	// progress is an optional cancellation callback (return false to abort);
	// it is invoked once per scanned 2 MB window with the current physical address.
	uint64_t FindSystemCr3(FnProgress progress = nullptr);

	// Cached values filled by Initialize().
	uint64_t kernel_base()  const { return kernelbase_; }
	uint64_t system_cr3pa() const { return system_cr3pa_; }

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
		~ScopedMap() { if (owns && unmap && *unmap) (*unmap)(va); }
	};

	// Resolves the physical-address mask (MAXPHYADDR) once and caches it.
	static uint64_t PaddrMask();

	// Returns true iff callbacks are usable.
	bool CallbacksValid() const { return static_cast<bool>(fn_pa_map_) && static_cast<bool>(fn_pa_unmap_); }

	// SEH / exception-safe helpers. SehCopy is the single __try/__except leaf
	// (no C++ destructors in its frame, as required under MSVC /EHsc); the
	// SehRead* wrappers own mappings via ScopedMap and delegate the actual
	// memory read to SehCopy. Defined out-of-line below.
	static bool SehCopy(void* dst, const void* src, size_t n);
	static bool SehReadPte(uint64_t ptePa, uint64_t* out,
	                       const FnMap& fm, const FnUnMap& fu);
	static bool SehReadMagic(uint64_t pa, uint16_t* outMagic, uint32_t* outLfanew,
	                         const FnMap& fm, const FnUnMap& fu);
	static bool SehReadPml4e511(const uint8_t* pageBase, uint64_t* out);

	// Attempt to enable SeDebugPrivilege (required by EnumDeviceDrivers on
	// Windows 11 24H2+); returns true on success. Failure is non-fatal on
	// older Windows versions where the privilege is not enforced.
	static bool EnableSeDebugPrivilege();

	// reserved for direct IOCTL usage by consumers / subclasses
	HANDLE   hDevice_      = INVALID_HANDLE_VALUE;
	uint64_t kernelbase_   = 0;
	uint64_t system_cr3pa_ = 0;
	FnMap    fn_pa_map_;
	FnUnMap  fn_pa_unmap_;
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
                             const FnMap& fm, const FnUnMap& fu)
{
	uintptr_t mapped = 0;
	if (!fm(ptePa & ~0xFFFull, &mapped, 0x1000))
		return false;

	ScopedMap guard{ &fu, mapped, true };
	return SehCopy(out, reinterpret_cast<const void*>(mapped + (ptePa & 0xFFFull)),
	               sizeof(uint64_t));
}

// Reads the MZ magic and e_lfanew from the first page of a kernel image.
// The mapping is ScopedMap-owned; reads go through SehCopy so any access
// violation is reported as a failure rather than tearing down the caller.
inline bool Mmio::SehReadMagic(uint64_t pa, uint16_t* outMagic, uint32_t* outLfanew,
                               const FnMap& fm, const FnUnMap& fu)
{
	uintptr_t mapped = 0;
	if (!fm(pa & ~0xFFFull, &mapped, 0x1000))
		return false;

	ScopedMap guard{ &fu, mapped, true };
	const uint8_t* base = reinterpret_cast<const uint8_t*>(mapped + (pa & 0xFFFull));
	if (!SehCopy(outMagic, base, sizeof(uint16_t)))
		return false;
	// e_lfanew is at offset 0x3C of the DOS header.
	return SehCopy(outLfanew, base + 0x3C, sizeof(uint32_t));
}

// PML4[511] presence check for a candidate System CR3.
// pageBase is already mapped by the caller; this is a pure read helper.
inline bool Mmio::SehReadPml4e511(const uint8_t* pageBase, uint64_t* out)
{
	return SehCopy(out, pageBase + 0x1FF * 8, sizeof(uint64_t));
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
		__cpuidex(cpuInfo, static_cast<int>(0x80000008), 0);
		unsigned int maxPaBits = static_cast<unsigned int>(cpuInfo[0] & 0xFFu);
		if (maxPaBits == 0 || maxPaBits >= 64) maxPaBits = 52; // defensive default
		return ((1ull << maxPaBits) - 1ull) & ~0xFFFull;
	}();
	return mask;
}

inline bool Mmio::Initialize()
{
	last_status_ = MmioStatus::Ok;
	last_error_  = 0;

	if (!CallbacksValid()) {
		last_status_ = MmioStatus::BadCallbacks;
		return false;
	}

	// On Windows 11 24H2+ EnumDeviceDrivers requires SeDebugPrivilege.
	// Best-effort enable — if it fails on older Windows, GetKernelBase()
	// can still succeed without it.
	EnableSeDebugPrivilege();

	kernelbase_ = GetKernelBase();
	if (!kernelbase_) {
		last_status_ = MmioStatus::NoKernelBase;
		return false;
	}

	system_cr3pa_ = FindSystemCr3();
	if (!system_cr3pa_) {
		last_status_ = MmioStatus::NoSystemCr3;
		return false;
	}

	last_status_ = MmioStatus::Ok;
	return true;
}

inline bool Mmio::ReadPhysicalMemory(uint64_t pa, void* buf, size_t size)
{
	last_error_  = 0;
	last_status_ = MmioStatus::Ok;

	if (!CallbacksValid()) {
		last_status_ = MmioStatus::BadCallbacks;
		return false;
	}
	if (size == 0)                return true;   // nothing to do
	if (buf == nullptr)           { last_status_ = MmioStatus::InternalError; return false; }

	const uintptr_t pageOffset   = static_cast<uintptr_t>(pa & 0xFFFull);
	const size_t    requiredSize = pageOffset + size;
	// A single mapping window covers at most one page boundary crossing, i.e.
	// pageOffset + size must not exceed 0x2000. Larger or multi-page requests
	// must be segmented by the caller (e.g. ReadKernelMemory).
	if (requiredSize > 0x2000) {
		last_status_ = MmioStatus::InternalError;
		return false;
	}
	const size_t mapSize = (requiredSize > 0x1000) ? 0x2000 : 0x1000;
	const uint64_t alignedPa = pa & ~0xFFFull;

	uintptr_t mapped = 0;
	if (!fn_pa_map_(alignedPa, &mapped, mapSize)) {
		last_status_ = MmioStatus::MappingFailed;
		return false;
	}

	ScopedMap guard{ &fn_pa_unmap_, mapped, true };

	const bool ok = SehCopy(buf, reinterpret_cast<void*>(mapped + pageOffset), size);
	if (!ok)
		last_status_ = MmioStatus::InternalError;
	return ok;
}

inline bool Mmio::WritePhysicalMemory(uint64_t pa, const void* buf, size_t size)
{
	last_error_  = 0;
	last_status_ = MmioStatus::Ok;

	if (!CallbacksValid()) {
		last_status_ = MmioStatus::BadCallbacks;
		return false;
	}
	if (size == 0)                return true;
	if (buf == nullptr)           { last_status_ = MmioStatus::InternalError; return false; }

	const uintptr_t pageOffset   = static_cast<uintptr_t>(pa & 0xFFFull);
	const size_t    requiredSize = pageOffset + size;
	if (requiredSize > 0x2000) {
		last_status_ = MmioStatus::InternalError;
		return false;
	}
	const size_t mapSize = (requiredSize > 0x1000) ? 0x2000 : 0x1000;
	const uint64_t alignedPa = pa & ~0xFFFull;

	uintptr_t mapped = 0;
	if (!fn_pa_map_(alignedPa, &mapped, mapSize)) {
		last_status_ = MmioStatus::MappingFailed;
		return false;
	}

	ScopedMap guard{ &fn_pa_unmap_, mapped, true };

	const bool ok = SehCopy(reinterpret_cast<void*>(mapped + pageOffset), buf, size);
	if (!ok)
		last_status_ = MmioStatus::InternalError;
	return ok;
}

inline bool Mmio::ReadKernelMemory(uint64_t va, void* buf, size_t size)
{
	last_error_  = 0;
	last_status_ = MmioStatus::Ok;

	if (!CallbacksValid()) {
		last_status_ = MmioStatus::BadCallbacks;
		return false;
	}
	if (buf == nullptr && size > 0) {
		last_status_ = MmioStatus::InternalError;
		return false;
	}

	uint8_t* out = static_cast<uint8_t*>(buf);
	size_t    remaining = size;
	uint64_t  cur       = va;

	while (remaining > 0) {
		const size_t inPage = 0x1000 - static_cast<size_t>(cur & 0xFFFull);
		const size_t seg    = (remaining < inPage) ? remaining : inPage;

		const uint64_t pa = VaToPa(cur);
		if (!pa) return false;   // VaToPa() already set last_status_ = TranslationFailed
		if (!ReadPhysicalMemory(pa, out, seg)) return false;  // status already set

		out       += seg;
		cur       += seg;
		remaining -= seg;
	}
	return true;
}

inline bool Mmio::WriteKernelMemory(uint64_t va, const void* buf, size_t size)
{
	last_error_  = 0;
	last_status_ = MmioStatus::Ok;

	if (!CallbacksValid()) {
		last_status_ = MmioStatus::BadCallbacks;
		return false;
	}
	if (buf == nullptr && size > 0) {
		last_status_ = MmioStatus::InternalError;
		return false;
	}

	const uint8_t* in = static_cast<const uint8_t*>(buf);
	size_t    remaining = size;
	uint64_t  cur       = va;

	while (remaining > 0) {
		const size_t inPage = 0x1000 - static_cast<size_t>(cur & 0xFFFull);
		const size_t seg    = (remaining < inPage) ? remaining : inPage;

		const uint64_t pa = VaToPa(cur);
		if (!pa) return false;   // VaToPa() already set last_status_ = TranslationFailed
		if (!WritePhysicalMemory(pa, in, seg)) return false;  // status already set

		in        += seg;
		cur       += seg;
		remaining -= seg;
	}
	return true;
}

inline uint64_t Mmio::VaToPa(uint64_t va, uint64_t cr3pa)
{
	last_error_  = 0;
	last_status_ = MmioStatus::Ok;

	if (!cr3pa)
		cr3pa = system_cr3pa_;
	if (!cr3pa) {                          // no CR3 available
		last_status_ = MmioStatus::TranslationFailed;
		return 0;
	}
	if (!CallbacksValid()) {               // can't walk PTEs without the map callbacks
		last_status_ = MmioStatus::BadCallbacks;
		return 0;
	}

	const uint64_t PADDR_MASK     = PaddrMask();
	constexpr uint64_t PTE_PRESENT    = (1ull << 0);
	constexpr uint64_t PTE_LARGE_PAGE = (1ull << 7);

	// --- Paging mode detection ---------------------------------------------
	// Decide whether the OS is actually using 5-level (LA57) paging for THIS
	// address space. CPUID(7,0):ECX[16] only reports CPU *capability*; many
	// modern CPUs set it while Windows still runs 4-level paging, so using the
	// capability bit directly breaks every such machine. We instead judge by
	// the canonical form of the running kernel's image VA:
	//   4-level canonical kernel half: bits[63:48] == 0xFFFF (sign-ext bit 47)
	//   5-level canonical kernel half: bits[63:56] == 0xFF, bits[55:48] not
	//                                  all ones (sign-extended bit 56)
	// (A simple '>> 56' test would be non-zero for BOTH layouts since the top
	//  byte is 0xFF in either case, so the test must inspect bits[55:48].)
	const uint64_t refVa       = (va >= 0xFFFF800000000000ull) ? va : kernelbase_;
	// When kernelbase_ is not yet cached and va is a user-mode address,
	// default to 4-level paging (the Windows default on virtually all
	// x64 systems, including LA57-capable CPUs running 4-level mode).
	const bool    looks4Level = (refVa != 0) ? ((refVa >> 48) == 0xFFFFull) : true;
	const int     vaBits      = looks4Level ? 48 : 57;
	const int     startIdx    = looks4Level ? 1 : 0;

	const uint8_t shifts[] = { 48, 39, 30, 21, 12 };   // PML5→PML4→PDPT→PD→PT

	// Canonical-address check
	const uint64_t topBits = va >> (vaBits - 1);
	const uint64_t topMask = (1ull << (64 - vaBits + 1)) - 1;
	if (topBits != 0 && topBits != topMask) {
		last_status_ = MmioStatus::TranslationFailed;
		return 0;
	}

	// --- Page-table walk ---------------------------------------------------
	uint64_t pagingBase = cr3pa & PADDR_MASK;
	uint64_t pteValue   = 0;

	for (int i = startIdx; i < 5; ++i) {
		const uint64_t idx   = (va >> shifts[i]) & 0x1FFull;
		const uint64_t ptePa = pagingBase + idx * sizeof(uint64_t);

		// Use the SEH-protected leaf so a transient mapping fault does not
		// tear down the whole walk.
		if (!SehReadPte(ptePa, &pteValue, fn_pa_map_, fn_pa_unmap_)) {
			last_status_ = MmioStatus::TranslationFailed;
			return 0;
		}
		if (!(pteValue & PTE_PRESENT)) {
			last_status_ = MmioStatus::TranslationFailed;
			return 0;
		}

		// Large-page (PS bit set) can only designate a leaf at PDPT (1 GB) or
		// PD (2 MB). PML4's PS bit is reserved and must be treated as a
		// regular page-directory pointer (continue the walk).
		if (pteValue & PTE_LARGE_PAGE) {
			if (i == 2) {
				// 1 GB page (PDPT entry, PS=1)
				const uint64_t pageMask = PADDR_MASK & ~((1ull << 30) - 1);
				return (pteValue & pageMask) | (va & 0x3FFFFFFFull);
			}
			if (i == 3) {
				// 2 MB page (PD entry, PS=1)
				const uint64_t pageMask = PADDR_MASK & ~((1ull << 21) - 1);
				return (pteValue & pageMask) | (va & 0x1FFFFFull);
			}
			// PS set at PML4 (i==1) is reserved -> ignore and continue walk.
		}

		pagingBase = pteValue & PADDR_MASK;
	}

	// i == 4 reached: pteValue is a PT entry (4 KB leaf).
	return (pteValue & PADDR_MASK) | (va & 0xFFFull);
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

	// Size query: passing cb = 0 always returns FALSE with
	// ERROR_INSUFFICIENT_BUFFER and writes the required byte count to
	// *lpcbNeeded — this is the documented, expected "query" path, NOT an
	// error to retry. The previous implementation treated this FALSE as a
	// retry and re-zeroed cbNeeded each iteration, so the allocation path was
	// unreachable and GetKernelBase() always returned 0 (Initialize() then
	// always failed with NoKernelBase).
	DWORD cbNeeded = 0;
	if (!EnumDeviceDrivers(nullptr, 0, &cbNeeded)) {
		last_error_ = GetLastError();
		if (last_error_ != ERROR_INSUFFICIENT_BUFFER)
			return 0;   // genuine failure — no kernel image retrievable
		// else: cbNeeded holds the required size (the expected, normal path).
	}
	if (cbNeeded == 0)
		return 0;

	// The driver set can change between the size query and the data call; only
	// THAT failure is worth retrying (re-querying the size each retry).
	for (int attempt = 0; attempt < 3; ++attempt) {
		const size_t count = cbNeeded / sizeof(LPVOID);
		std::vector<LPVOID> drivers(count ? count : 1);
		DWORD cbNeeded2 = 0;
		if (!EnumDeviceDrivers(drivers.data(),
		                      static_cast<DWORD>(drivers.size() * sizeof(LPVOID)),
		                      &cbNeeded2)) {
			last_error_ = GetLastError();
			if (last_error_ == ERROR_INSUFFICIENT_BUFFER && attempt < 2) {
				cbNeeded = cbNeeded2;   // grow to the new required size and retry
				continue;
			}
			return 0;
		}
		if (cbNeeded2 == 0 || drivers.empty())
			return 0;

		// On Windows 11 24H2+, EnumDeviceDrivers returns TRUE but fills
		// the array with NULLs when SeDebugPrivilege is missing.
		if (!drivers[0]) {
			last_error_ = ERROR_PRIVILEGE_NOT_HELD;
			return 0;
		}

		// First driver in the enumeration is the NT kernel image.
		return reinterpret_cast<uint64_t>(drivers[0]);
	}
	return 0;
}

inline uint64_t Mmio::FindSystemCr3(FnProgress progress)
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

	// Query the actual amount of installed physical memory.
	ULONGLONG totalMemoryKiB = 0;
	uint64_t  maxPa = 0;
	if (GetPhysicallyInstalledSystemMemory(&totalMemoryKiB) && totalMemoryKiB > 0)
		maxPa = totalMemoryKiB * 1024;            // KiB → bytes
	else
		maxPa = 0x2000000000ull;                  // fallback: 128 GB

	// Scan in 2 MB windows. If a 2 MB mapping is rejected by the callback we
	// fall back to 4 KB granularity for that region instead of skipping it.
	constexpr uint64_t chunkSize = 0x200000;       // 2 MB
	constexpr uint64_t pageSize  = 0x1000;         // 4 KB

	// Start from the first physical page (0x0). Physical page 0 is usually
	// reserved by firmware, but a CR3 table could theoretically reside there.
	for (uint64_t pa = 0x0; pa < maxPa; pa += chunkSize) {
		if (progress && !progress(pa))
			return 0;   // cancelled

		uintptr_t chunkVa = 0;
		const uint8_t* chunkBuf = nullptr;
		bool chunkMapped = false;
		if (fn_pa_map_(pa, &chunkVa, chunkSize)) {
			chunkBuf    = reinterpret_cast<const uint8_t*>(chunkVa);
			chunkMapped = true;
		}
		// RAII guard for the 2 MB chunk mapping. The previous implementation
		// released the chunk with a manual call only AFTER the inner loop; if a
		// callback threw inside VaToPa()/SehReadPte() during the loop, stack
		// unwinding skipped that unmap and leaked the 2 MB mapping. ScopedMap
		// guarantees release on every exit (break / return / exception),
		// matching the README's stated exception-safety guarantee.
		ScopedMap chunkGuard{ &fn_pa_unmap_, chunkVa, chunkMapped };

		bool     found     = false;
		uint64_t resultCr3 = 0;

		for (uint64_t offset = 0; offset < chunkSize; offset += pageSize) {
			const uint64_t cr3Candidate = pa + offset;
			const uint8_t* pageBase = nullptr;

			// Prefer the bulk 2 MB mapping; otherwise map this single 4 KB
			// page directly so drivers that only support page-granularity
			// mappings can still locate the CR3.
			uintptr_t pageVa = 0;
			bool      pageMapped = false;
			if (chunkMapped) {
				pageBase = chunkBuf + offset;
			} else {
				if (!fn_pa_map_(cr3Candidate, &pageVa, pageSize))
					continue;
				pageBase   = reinterpret_cast<const uint8_t*>(pageVa);
				pageMapped = true;
			}

			// Scoped RAII guard for the optional per-page mapping. Uses the
			// shared ScopedMap (the former local PgGuard, now deduplicated) so
			// a thrown callback or any early exit still releases the mapping.
			ScopedMap pg{ &fn_pa_unmap_, pageVa, pageMapped };

			// PML4[511] must be present (maps the higher half).
			uint64_t pml4e511 = 0;
			if (!SehReadPml4e511(pageBase, &pml4e511))
				continue;
			if (!(pml4e511 & 1))
				continue;

			// Translate the kernel base through this candidate CR3.
			const uint64_t kernelPa = VaToPa(kernelbase_, cr3Candidate);
			if (!kernelPa)
				continue;

			// Map the kernel's PE header and verify "MZ" plus e_lfanew/PE sig.
			uint16_t magic = 0;
			uint32_t lfanew = 0;
			if (!SehReadMagic(kernelPa, &magic, &lfanew, fn_pa_map_, fn_pa_unmap_))
				continue;
			if (magic != 0x5A4D)           // "MZ"
				continue;

			// Secondary validation: the NT image headers must carry "PE\0\0".
			// e_lfanew is the offset of the PE header from the image base.
			if (lfanew == 0 || lfanew > 0x400)   // sanity bound for a DOS stub
				continue;

			const uint64_t peHdrPa = VaToPa(kernelbase_ + lfanew, cr3Candidate);
			if (!peHdrPa)
				continue;

			uint32_t peSig = 0;
			if (!ReadPhysicalMemory(peHdrPa, &peSig, sizeof(peSig)))
				continue;
			if (peSig != 0x00004550)       // "PE\0\0"
				continue;

			resultCr3 = cr3Candidate;
			found     = true;
			break;
		}

		if (found)
			return resultCr3;   // chunkGuard unmaps the 2 MB chunk on return/unwind
	}

	last_status_ = MmioStatus::NoSystemCr3;   // scan exhausted without a match
	return 0;
}