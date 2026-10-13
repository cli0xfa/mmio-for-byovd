// Test / sample harness for mmio-for-byovd.
//
// WinIo64.sys is embedded as an RCDATA resource (see resource.rc), extracted
// to a temp file, registered as a kernel-driver service, and started. The
// driver exposes \\.\WinIo with two IOCTLs we care about (see the reverse
// report WinIo_Reverse_Report.md):
//
//   0x80102040  MapPhysicalMemory   METHOD_BUFFERED, in/out 0x28-byte struct
//   0x80102044  UnmapPhysicalMemory METHOD_BUFFERED, in     0x28-byte struct
//
// Those become the FnMap / FnUnMap callbacks consumed by the mmio library,
// which then runs the real test scenarios: locate ntoskrnl, scan a kernel CR3,
// translate kernel VAs, and read kernel memory.

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <unordered_map>

#include "resource.h"
#include "../../mmio-for-byovd/mmio.hpp"

// ---------------------------------------------------------------------------
// WinIo on-the-wire structures (per WinIo_Reverse_Report.md)
// ---------------------------------------------------------------------------
//
// WINIO_MAP_BUFFER: 0x28 bytes. For Map, the caller fills CommitSize +
// BusAddress; the driver returns SectionHandle / BaseAddress / SectionObject.
// For Unmap, the caller passes back the *complete* map struct the driver
// returned. We therefore must remember the full struct per live mapping.
// x64 natural alignment yields exactly 0x28 — no #pragma pack needed.
struct WinIoMapBuffer
{
	uint64_t CommitSize;     // +0x00  mapping size, bytes
	uint64_t BusAddress;     // +0x08  physical address (PHYSICAL_ADDRESS.QP)
	HANDLE  SectionHandle;   // +0x10  driver output / unmap input
	void*   BaseAddress;     // +0x18  mapped VA     (driver output / unmap input)
	void*   SectionObject;   // +0x20  section object (driver output / unmap input)
};
static_assert(sizeof(WinIoMapBuffer) == 0x28, "WinIoMapBuffer must be 0x28 bytes");

constexpr DWORD kIoctlMap   = 0x80102040;
constexpr DWORD kIoctlUnmap = 0x80102044;

// ---------------------------------------------------------------------------
// Tiny test harness — no external framework, just named checks.
// ---------------------------------------------------------------------------
static int g_pass = 0, g_fail = 0, g_skip = 0;

static void Pass(const char* n) { printf("  [PASS] %s\n", n); ++g_pass; }
static void Fail(const char* n) { printf("  [FAIL] %s\n", n); ++g_fail; }
static void Skip(const char* n, const char* why)
{ printf("  [SKIP] %s (%s)\n", n, why); ++g_skip; }

static const char* StatusName(MmioStatus s)
{
	switch (s) {
	case MmioStatus::Ok:                  return "Ok";
	case MmioStatus::BadCallbacks:       return "BadCallbacks";
	case MmioStatus::NoKernelBase:        return "NoKernelBase";
	case MmioStatus::NoKernelCr3:         return "NoKernelCr3";
	case MmioStatus::MappingFailed:       return "MappingFailed";
	case MmioStatus::TranslationFailed:   return "TranslationFailed";
	case MmioStatus::NoSeDebugPrivilege:  return "NoSeDebugPrivilege";
	case MmioStatus::Cancelled:           return "Cancelled";
	case MmioStatus::InternalError:       return "InternalError";
	case MmioStatus::InvalidArgument:     return "InvalidArgument";
	case MmioStatus::NotInitialized:      return "NotInitialized";
	case MmioStatus::UnsupportedPagingMode:return "UnsupportedPagingMode";
	case MmioStatus::PhysicalRangesUnavailable:return "PhysicalRangesUnavailable";
	case MmioStatus::InvalidPhysicalRange: return "InvalidPhysicalRange";
	case MmioStatus::AccessDenied:         return "AccessDenied";
	}
	return "?";
}

// ---------------------------------------------------------------------------
// Privilege helper: enable SeDebugPrivilege for SCM service-control calls.
// GetKernelBase() now enables it itself before EnumDeviceDrivers.
// ---------------------------------------------------------------------------
static void EnableDebugPrivilege()
{
	HANDLE tok = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
		return;
	TOKEN_PRIVILEGES tp{};
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
		AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
	CloseHandle(tok);
}

// ---------------------------------------------------------------------------
// Resource extraction — pulls IDR_WINIO_BIN out of the exe and drops it to
// `outPath`. Returns true on success.
// ---------------------------------------------------------------------------
static bool ExtractDriverResource(HMODULE hSelf, const std::wstring& outPath)
{
	HRSRC hRes = FindResourceW(hSelf, MAKEINTRESOURCEW(IDR_WINIO_BIN), RT_RCDATA);
	if (!hRes) return false;
	HGLOBAL hMem = LoadResource(hSelf, hRes);
	if (!hMem) return false;
	DWORD sz = SizeofResource(hSelf, hRes);
	void* p  = LockResource(hMem);
	if (!p || !sz) return false;

	HANDLE hFile = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, nullptr,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) return false;
	DWORD written = 0;
	BOOL ok = WriteFile(hFile, p, sz, &written, nullptr) && written == sz;
	CloseHandle(hFile);
	if (!ok) DeleteFileW(outPath.c_str());
	return ok == TRUE;
}

// ---------------------------------------------------------------------------
// Kernel driver lifecycle: install + start the service from the dropped copy
// of the embedded .sys, then stop + delete on teardown.
// ---------------------------------------------------------------------------
class DriverLoader
{
	SC_HANDLE scm_ = nullptr, svc_ = nullptr;
public:
	bool Install(const std::wstring& binPath)
	{
		scm_ = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
		if (!scm_) return false;

		// Sweep any stale instance first (SIG hasn't been loaded yet).
		if (SC_HANDLE stale = OpenServiceW(scm_, svcName_, SERVICE_ALL_ACCESS)) {
			SERVICE_STATUS st{};
			ControlService(stale, SERVICE_CONTROL_STOP, &st);
			DeleteService(stale);
			CloseServiceHandle(stale);
			Sleep(250);
		}

		svc_ = CreateServiceW(scm_, svcName_, svcName_,
			SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, binPath.c_str(),
			nullptr, nullptr, nullptr, nullptr, nullptr);

		if (!svc_) {
			const DWORD err = GetLastError();
			if (err == ERROR_SERVICE_EXISTS
				|| err == ERROR_SERVICE_MARKED_FOR_DELETE) {
				svc_ = OpenServiceW(scm_, svcName_, SERVICE_ALL_ACCESS);
			}
		}
		return svc_ != nullptr;
	}

	bool Start() const
	{
		if (!svc_) return false;
		if (StartServiceW(svc_, 0, nullptr)) return true;
		const DWORD err = GetLastError();
		// Already running is effectively success; anything else is a real
		// load failure (blocklist / signature / test-signing off / HVCI on).
		return err == ERROR_SERVICE_ALREADY_RUNNING;
	}

	void Uninstall()
	{
		if (svc_) {
			SERVICE_STATUS st{};
			ControlService(svc_, SERVICE_CONTROL_STOP, &st);
			DeleteService(svc_);
			CloseServiceHandle(svc_);
			svc_ = nullptr;
		}
		if (scm_) { CloseServiceHandle(scm_); scm_ = nullptr; }
	}

	~DriverLoader() { Uninstall(); }
private:
	static constexpr const wchar_t* svcName_ = L"WinIo_mmio_test";
};

// ---------------------------------------------------------------------------
// WinIo-backed map/unmap + bookkeeping for the mmio callbacks.
//
// A live-mapping table keyed by the mapped BaseAddress remembers the full
// WinIoMapBuffer between FnMap and the matching FnUnMap (FnUnMap must hand
// the original SectionHandle / SectionObject back to the driver). The mutex
// guards only the table, never an in-flight DeviceIoControl, so VaToPa's
// nested map→unmap (a 2 MB chunk live while translating PTE pages via 4 KB
// maps) needs no recursive lock.
// ---------------------------------------------------------------------------
struct WinIoContext
{
	HANDLE device = INVALID_HANDLE_VALUE;
	std::mutex mtx;
	std::unordered_map<uintptr_t, WinIoMapBuffer> live;
};

static bool WinIoMap(WinIoContext& ctx, uint64_t pa, uintptr_t* outVa, size_t size)
{
	if (ctx.device == INVALID_HANDLE_VALUE) return false;

	WinIoMapBuffer buf{};
	buf.CommitSize = size;
	buf.BusAddress = pa;                 // PHYSICAL_ADDRESS.QP is a 64-bit int

	DWORD ret = 0;
	if (!DeviceIoControl(ctx.device, kIoctlMap,
		&buf, sizeof(buf), &buf, sizeof(buf), &ret, nullptr))
		return false;
	if (!buf.BaseAddress) return false;

	*outVa = reinterpret_cast<uintptr_t>(buf.BaseAddress);
	{
		std::lock_guard<std::mutex> lk(ctx.mtx);
		ctx.live[*outVa] = buf;          // remember the full struct for Unmap
	}
	return true;
}

static void WinIoUnmap(WinIoContext& ctx, uintptr_t va)
{
	if (ctx.device == INVALID_HANDLE_VALUE) return;

	WinIoMapBuffer buf{};
	bool have = false;
	{
		std::lock_guard<std::mutex> lk(ctx.mtx);
		auto it = ctx.live.find(va);
		if (it != ctx.live.end()) { buf = it->second; ctx.live.erase(it); have = true; }
	}
	if (!have) return;

	DWORD ret = 0;
	DeviceIoControl(ctx.device, kIoctlUnmap,
		&buf, sizeof(buf), nullptr, 0, &ret, nullptr);
}

// ===========================================================================
// Test scenarios. The first two run without the driver loaded; the rest
// require WinIo to be mapped in so FnMap/FnUnMap are real.
// ===========================================================================

// BadCallbacks: a Mmio with empty callbacks must short-circuit at Initialize
// with MmioStatus::BadCallbacks and NOT proceed to touch EnumDeviceDrivers.
// Passes without admin or the driver.
static void TestBadCallbacks()
{
	puts("[*] test: empty callbacks are rejected");
	Mmio m(nullptr, nullptr, nullptr);   // both std::function args are null
	const bool ok = m.Initialize();
	if (!ok && m.last_status() == MmioStatus::BadCallbacks)
		Pass("Initialize rejects null callbacks");
	else
		Fail("Initialize rejects null callbacks");

	// Direct VA translation with no callbacks must also fail safely. Pass a
	// NON-ZERO cr3pa so VaToPa skips its "no CR3 cached" early-out (the lib
	// checks CR3 availability *before* callback validity) and actually reaches
	// the CallbacksValid() guard — otherwise a cr3pa=0 call with no cached
	// kernel_cr3pa_ returns TranslationFailed, not BadCallbacks.
	if (m.VaToPa(0xFFFF800000000000ull, /*cr3pa=*/1) == 0
		&& m.last_status() == MmioStatus::BadCallbacks)
		Pass("VaToPa rejects no callbacks");
	else
		Fail("VaToPa rejects no callbacks");
}

// Read/WritePhysicalMemory single-window overflow guard drives the
// early-reject of size > 0x2000 — needs *valid* callbacks so we reach the
// size branch (a null-callback Mmio short-circuits first on BadCallbacks).
// No memory is actually touched: the map callback always returns false, but
// the size check runs before any mapping is attempted.
static void TestSizeBoundNoDriver()
{
	puts("[*] test: Read/WritePhysicalMemory size bound (no driver, no mem)");
	int mapCalls = 0;
	Mmio m(nullptr,
		[&mapCalls](uint64_t, uintptr_t*, size_t) { ++mapCalls; return false; },
		[](uintptr_t) {});
	uint8_t tmp[1] = {};

	(void)m.ReadPhysicalMemory(0, tmp, 0x2001);
	if (m.last_status() == MmioStatus::InvalidArgument)
		Pass("ReadPhysicalMemory early-rejects size > 0x2000");
	else
		Fail("ReadPhysicalMemory early-rejects size > 0x2000");

	(void)m.WritePhysicalMemory(0, tmp, 0x2001);
	if (m.last_status() == MmioStatus::InvalidArgument)
		Pass("WritePhysicalMemory early-rejects size > 0x2000");
	else
		Fail("WritePhysicalMemory early-rejects size > 0x2000");

	(void)m.ReadPhysicalMemory(0, tmp, 0);
	if (m.last_status() == MmioStatus::InvalidArgument && mapCalls == 0)
		Pass("zero-length physical read rejected before mapping");
	else
		Fail("zero-length physical read rejected before mapping");

	(void)m.ReadPhysicalMemory(UINT64_MAX, tmp, 1);
	if (m.last_status() == MmioStatus::InvalidArgument && mapCalls == 0)
		Pass("overflowing physical range rejected before mapping");
	else
		Fail("overflowing physical range rejected before mapping");

	uint8_t kernelByte = 0;
	(void)m.ReadKernelMemory(0xFFFF800000000000ull, &kernelByte, 1);
	if (m.last_status() == MmioStatus::NotInitialized && mapCalls == 0)
		Pass("kernel read requires successful initialization");
	else
		Fail("kernel read requires successful initialization");

	int unmapCalls = 0;
	Mmio nullMapping(nullptr,
		[](uint64_t, uintptr_t* out, size_t) { *out = 0; return true; },
		[&unmapCalls](uintptr_t) { ++unmapCalls; });
	(void)nullMapping.ReadPhysicalMemory(0, tmp, 1);
	if (nullMapping.last_status() == MmioStatus::InvalidArgument && unmapCalls == 1)
		Pass("successful zero-address mapping is rejected and released");
	else
		Fail("successful zero-address mapping is rejected and released");
}

// Initialization: GetKernelBase + FindKernelCr3 both succeed → cached values.
static void TestInitialize(Mmio& m)
{
	puts("[*] test: Initialize");
	if (m.Initialize()
		&& m.kernel_base()  != 0
		&& m.kernel_cr3pa() != 0
		&& m.last_status()  == MmioStatus::Ok)
		Pass("Initialize fills kernel_base + kernel_cr3pa");
	else
		Fail("Initialize fills kernel_base + kernel_cr3pa");
}

static void TestKernelBaseIndependent(Mmio& m)
{
	puts("[*] test: GetKernelBase independent");
	if (m.GetKernelBase() != 0) Pass("GetKernelBase returns non-zero");
	else Fail("GetKernelBase returns non-zero");
}

static void TestReadMz(Mmio& m)
{
	puts("[*] test: read kernel MZ DOS header");
	uint16_t mz = 0;
	if (m.ReadKernelMemory(m.kernel_base(), &mz, sizeof(mz))
		&& mz == 0x5A4D)
		Pass("ReadKernelMemory(kernel_base) reads MZ (0x5A4D)");
	else
		Fail("ReadKernelMemory(kernel_base) reads MZ (0x5A4D)");
}

// Read the e_lfanew offset and then the "PE\0\0" signature at kernel_base +
// lfanew — exercises VaToPa on a non-zero offset and a small in-page read.
static void TestPeSignature(Mmio& m)
{
	puts("[*] test: parse PE signature via translation");
	uint32_t lfanew = 0;
	if (!m.ReadKernelMemory(m.kernel_base() + 0x3C, &lfanew, sizeof(lfanew))) {
		Fail("read e_lfanew at kernel_base+0x3C");
		return;
	}
	if (lfanew == 0 || lfanew > 0x400) {
		Fail("e_lfanew sanity (out of DOS-stub range)");
		return;
	}
	uint32_t pe = 0;
	if (m.ReadKernelMemory(m.kernel_base() + lfanew, &pe, sizeof(pe))
		&& pe == 0x00004550u)
		Pass("read 'PE\\0\\0' signature at kernel_base+e_lfanew");
	else
		Fail("read 'PE\\0\\0' signature at kernel_base+e_lfanew");
}

// Cross-page read straddling a 4 KB boundary — verifies ReadKernelMemory's
// segmenting loop produces contiguity across two separately-translated pages.
// Uses an offset well past the first page so the straddle is always real.
static void TestCrossPageRead(Mmio& m)
{
	puts("[*] test: cross-page kernel read");
	const uint64_t kbase = m.kernel_base();
	// Pick a boundary a couple pages into the image so both sides are mapped.
	const uint64_t pageA = (kbase & ~0xFFFull) + 0x2000ull;
	const uint64_t read  = pageA - 4ull;        // 4 bytes into the lower page ...
	uint8_t a[4] = {}, b[12] = {};              // ... then 12 bytes across the line.
	if (!m.ReadKernelMemory(read, b, sizeof(b))) {
		Fail("cross-page ReadKernelMemory");
		return;
	}
	if (!m.ReadKernelMemory(read, a, sizeof(a))) {
		Fail("aligned ref for cross-page");
		return;
	}
	if (memcmp(a, b, sizeof(a)) == 0)
		Pass("cross-page read matches lower-page prefix");
	else
		Fail("cross-page read matches lower-page prefix");
}

static void TestVaToPa(Mmio& m)
{
	puts("[*] test: VaToPa core paths");
	const uint64_t kbase = m.kernel_base();
	const uint64_t cr3   = m.kernel_cr3pa();

	if (m.VaToPa(kbase)      != 0) Pass("VaToPa(kernel_base) -> nonzero PA");
	else Fail("VaToPa(kernel_base) -> nonzero PA");
	if (m.VaToPa(kbase, cr3) != 0) Pass("VaToPa(kernel_base, cr3) -> nonzero PA");
	else Fail("VaToPa(kernel_base, cr3) -> nonzero PA");

	// Non-canonical user-half address must fail at the canonical check.
	if (m.VaToPa(0x0000DEADBEEF0000ull) == 0
		&& m.last_status() == MmioStatus::TranslationFailed)
		Pass("VaToPa(non-canonical) -> 0 + TranslationFailed");
	else
		Fail("VaToPa(non-canonical) -> 0 + TranslationFailed");

	// "most recent call" contract: a successful translate after a failure
	// must reset the status to Ok.
	if (m.VaToPa(kbase) && m.last_status() == MmioStatus::Ok)
		Pass("last_status resets to Ok on success after failure");
	else
		Fail("last_status resets to Ok on success after failure");
}

// Direct physical read: VaToPa then ReadPhysicalMemory on the single page the
// kernel image base lives on — exercises the non-chunked path.
static void TestReadPhysicalMemory(Mmio& m)
{
	puts("[*] test: ReadPhysicalMemory direct");
	const uint64_t pa = m.VaToPa(m.kernel_base());
	if (!pa) { Fail("VaToPa(kernel_base) for physical read"); return; }
	uint16_t mz = 0;
	if (m.ReadPhysicalMemory(pa, &mz, sizeof(mz)) && mz == 0x5A4D)
		Pass("ReadPhysicalMemory(pa of kernel_base) reads MZ");
	else
		Fail("ReadPhysicalMemory(pa of kernel_base) reads MZ");
}

// Write back the same bytes we just read — exercises WriteKernelMemory
// without altering any kernel state (the bytes are identical).
static void TestWriteBackUnchanged(Mmio& m)
{
	puts("[*] test: WriteKernelMemory write-back (invariant)");
	uint8_t before[8] = {}, after[8] = {};
	const uint64_t at = m.kernel_base();
	if (!m.ReadKernelMemory(at, before, sizeof(before)))   { Fail("pre-read for write-back");  return; }
	if (!m.WriteKernelMemory(at, before, sizeof(before)))   { Fail("WriteKernelMemory write-back"); return; }
	if (!m.ReadKernelMemory(at, after,  sizeof(after)))     { Fail("post-read for write-back"); return; }
	if (memcmp(before, after, sizeof(before)) == 0)
		Pass("WriteKernelMemory write-back preserves bytes");
	else
		Fail("WriteKernelMemory write-back preserves bytes");
}

// FindKernelCr3 with a progress callback that cancels immediately → must
// return 0 and set last_status() == Cancelled, but NOT wipe the cached CR3.
static void TestFindKernelCr3Cancel(Mmio& m)
{
	puts("[*] test: FindKernelCr3 cancel via progress");
	const uint64_t cached = m.kernel_cr3pa();
	const uint64_t got    = m.FindKernelCr3([](uint64_t) { return false; });
	if (got == 0
		&& m.last_status()   == MmioStatus::Cancelled
		&& m.kernel_cr3pa()  == cached)               // cache preserved through cancel
		Pass("FindKernelCr3(progress=false) -> 0 + Cancelled");
	else
		Fail("FindKernelCr3(progress=false) -> 0 + Cancelled");
}

// ---------------------------------------------------------------------------
int main()
{
	SetConsoleOutputCP(CP_UTF8);

	puts("==================================================================");
	puts(" mmio-for-byovd — WinIo64.sys test harness");
	puts("==================================================================");

	EnableDebugPrivilege();

	// --- Driver-independent tests ---------------------------------------
	TestBadCallbacks();
	TestSizeBoundNoDriver();

	// --- Extract the embedded driver to temp and install + start it -----
	const HMODULE hSelf = GetModuleHandleW(nullptr);
	std::wstring tmpDir(MAX_PATH, L'\0');
	DWORD tmpLen = GetTempPathW((DWORD)tmpDir.size(), tmpDir.data());
	if (tmpLen == 0 || tmpLen >= tmpDir.size()) {
		printf("[!] GetTempPathW failed: %lu\n", GetLastError());
		return (g_fail == 0) ? 0 : 1;
	}
	tmpDir.resize(tmpLen);

	std::wstring sysPath = tmpDir;
	sysPath += L"WinIo_mmio_test_";
	DWORD pid = GetCurrentProcessId();
	sysPath += std::to_wstring(pid);
	sysPath += L".sys";

	if (!ExtractDriverResource(hSelf, sysPath)) {
		printf("[!] could not extract embedded driver resource: %lu\n", GetLastError());
		Skip("all driver tests", "driver resource missing");
		printf("\n== Summary: %d passed, %d failed, %d skipped ==\n", g_pass, g_fail, g_skip);
		return (g_fail == 0) ? 0 : 1;
	}
	printf("[+] extracted driver -> %ls\n", sysPath.c_str());

	DriverLoader drv;
	if (!drv.Install(sysPath)) {
		printf("[!] InstallService failed: %lu (need admin?)\n", GetLastError());
		Skip("all driver tests", "service install failed");
		DeleteFileW(sysPath.c_str());
		printf("\n== Summary: %d passed, %d failed, %d skipped ==\n", g_pass, g_fail, g_skip);
		return (g_fail == 0) ? 0 : 1;
	}

	if (!drv.Start()) {
		const DWORD e = GetLastError();
		printf("[!] StartService failed: %lu\n", e);
		printf("    record the Windows error and policy state; keep security protections enabled.\n");
		Skip("all driver tests", "driver load failed (blocked / unsigned on this machine)");
		DeleteFileW(sysPath.c_str());
		printf("\n== Summary: %d passed, %d failed, %d skipped ==\n", g_pass, g_fail, g_skip);
		return (g_fail == 0) ? 0 : 1;
	}
	printf("[+] driver service started, \\Device\\WinIo live\n");

	HANDLE hDev = CreateFileW(L"\\\\.\\WinIo", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
		OPEN_EXISTING, 0, nullptr);
	if (hDev == INVALID_HANDLE_VALUE) {
		DWORD err = GetLastError();
		printf("[!] OpenDevice(\\\\.\\WinIo) failed: %lu\n", err);
		Skip("all driver tests",
			(err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
				? "device symlink not ready yet"
				: "device open error");
		DeleteFileW(sysPath.c_str());
		printf("\n== Summary: %d passed, %d failed, %d skipped ==\n", g_pass, g_fail, g_skip);
		return (g_fail == 0) ? 0 : 1;
	}

	// --- Build WinIo-backed callbacks and wire them into Mmio ------------
	WinIoContext ctx;
	ctx.device = hDev;

	auto fnMap   = [&ctx](uint64_t pa, uintptr_t* outVa, size_t sz) { return WinIoMap(ctx, pa, outVa, sz); };
	auto fnUnmap = [&ctx](uintptr_t va) { WinIoUnmap(ctx, va); };

	Mmio mmio(hDev, fnMap, fnUnmap, nullptr, /*ownsDeviceHandle=*/false);

	if (mmio.Initialize()) {
		printf("[+] Mmio::Initialize ok: kernel_base=0x%llx  kernel_CR3=0x%llx\n",
			(unsigned long long)mmio.kernel_base(),
			(unsigned long long)mmio.kernel_cr3pa());

		TestKernelBaseIndependent(mmio);
		TestReadMz(mmio);
		TestPeSignature(mmio);
		TestCrossPageRead(mmio);
		TestVaToPa(mmio);
		TestReadPhysicalMemory(mmio);
		TestWriteBackUnchanged(mmio);
		TestFindKernelCr3Cancel(mmio);

		// Re-run the Initialize passthrough assertions (re-caches, harmless)
		// to confirm the full Initialize contract independently of the
		// implicit Initialize we did above.
		TestInitialize(mmio);
	} else {
		printf("[!] Mmio::Initialize failed: status=%s err=%lu\n",
			StatusName(mmio.last_status()), mmio.last_error());
		Skip("driver test suite",
			"Initialize failed (no kernel base / CR3 via this driver)");
	}

	// --- Teardown --------------------------------------------------------
	CloseHandle(hDev);            // WinIo's CREATE/CLOSE handlers are no-ops
	drv.Uninstall();
	DeleteFileW(sysPath.c_str());

	// --- Summary ---------------------------------------------------------
	const int total = g_pass + g_fail + g_skip;
	printf("\n== Summary: %d/%d passed, %d failed, %d skipped ==\n",
		g_pass, total, g_fail, g_skip);
	return (g_fail == 0) ? 0 : 1;
}
