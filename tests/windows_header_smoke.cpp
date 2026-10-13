#include "mmio.hpp"

#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>
#include <utility>

static_assert(!std::is_copy_constructible_v<Mmio>);
static_assert(!std::is_copy_assignable_v<Mmio>);
static_assert(std::is_nothrow_move_constructible_v<Mmio>);
static_assert(std::is_nothrow_move_assignable_v<Mmio>);

namespace {
struct MockPhysicalMemory {
    std::unordered_map<uint64_t, std::array<uint8_t, 0x1000>> pages;
    int maps = 0;
    int unmaps = 0;

    void Put(uint64_t pa, uint64_t value)
    {
        const uint64_t page = pa & ~uint64_t{0xFFF};
        const size_t offset = static_cast<size_t>(pa & 0xFFF);
        auto& bytes = pages[page];
        std::memcpy(bytes.data() + offset, &value, sizeof(value));
    }

    void PutBytes(uint64_t pa, const uint8_t* source, size_t size)
    {
        for (size_t i = 0; i < size; ++i) {
            const uint64_t address = pa + i;
            pages[address & ~uint64_t{0xFFF}][static_cast<size_t>(address & 0xFFF)] = source[i];
        }
    }

    bool Map(uint64_t pa, uintptr_t* out, size_t size)
    {
        if (size != 0x1000) return false;
        const auto it = pages.find(pa & ~uint64_t{0xFFF});
        if (it == pages.end()) return false;
        *out = reinterpret_cast<uintptr_t>(it->second.data());
        ++maps;
        return true;
    }

    void Unmap(uintptr_t) { ++unmaps; }
};

int failures = 0;
void Check(bool value, const char* name)
{
    if (value) std::cout << "[PASS] " << name << '\n';
    else { std::cerr << "[FAIL] " << name << '\n'; ++failures; }
}

uint64_t Index(uint64_t va, unsigned shift) { return (va >> shift) & 0x1FF; }

void TestModelBackedTranslation()
{
    constexpr uint64_t va = 0xFFFF800012345678ull;
    MockPhysicalMemory memory;
    memory.Put(0x1000 + Index(va, 39) * 8, 0x2000 | 3);
    memory.Put(0x2000 + Index(va, 30) * 8, 0x3000 | 3);
    memory.Put(0x3000 + Index(va, 21) * 8, 0x4000 | 3);
    memory.Put(0x4000 + Index(va, 12) * 8, 0xABCDE000 | 0x83); // PAT on 4 KB PTE

    Mmio mmio(nullptr,
        [&memory](uint64_t pa, uintptr_t* out, size_t size) { return memory.Map(pa, out, size); },
        [&memory](uintptr_t address) { memory.Unmap(address); });
    const uint64_t pa = mmio.VaToPaWithMode(va, 0x1000, mmio_model::PagingMode::FourLevel);
    Check(pa == 0xABCDE678 && mmio.last_status() == MmioStatus::Ok,
          "public VA translator walks synthetic four-level tables");
    Check(memory.maps == memory.unmaps, "every successful PTE map is released once");

    const uint64_t unsupported = mmio.VaToPaWithMode(va, 0x1000, mmio_model::PagingMode::Unknown);
    Check(unsupported == 0 && mmio.last_status() == MmioStatus::UnsupportedPagingMode,
          "unknown page-table mode has a dedicated status");
}

void TestInvalidArgumentsAndMappingFailure()
{
    int mapCalls = 0;
    Mmio mmio(nullptr,
        [&mapCalls](uint64_t, uintptr_t*, size_t) { ++mapCalls; return false; },
        [](uintptr_t) {});
    uint8_t value = 0;
    Check(!mmio.ReadPhysicalMemory(0, &value, 0) &&
          mmio.last_status() == MmioStatus::InvalidArgument && mapCalls == 0,
          "zero-length physical read rejected before mapping");
    Check(!mmio.ReadPhysicalMemory(UINT64_MAX, &value, 1) &&
          mmio.last_status() == MmioStatus::InvalidArgument && mapCalls == 0,
          "overflowing physical range rejected before mapping");
    Check(!mmio.ReadPhysicalMemory(0, &value, 1) &&
          mmio.last_status() == MmioStatus::MappingFailed && mapCalls == 1,
          "mapping rejection has a specific status");
    mapCalls = 0;
    Check(mmio.VaToPaWithMode(0xFFFF800000000000ull, 0x1000,
                              mmio_model::PagingMode::FourLevel) == 0 &&
          mmio.last_status() == MmioStatus::MappingFailed && mapCalls == 1,
          "page-table mapping rejection remains distinguishable from translation failure");

    const IoResult detailed = mmio.ReadKernelMemoryDetailed(0xFFFF800000000000ull, &value, 1);
    Check(detailed.status == MmioStatus::NotInitialized && detailed.bytes_completed == 0,
          "detailed kernel read reports not initialized and zero completed bytes");
}

void TestNullMappingIsReleased()
{
    int unmaps = 0;
    Mmio mmio(nullptr,
        [](uint64_t, uintptr_t* out, size_t) { *out = 0; return true; },
        [&unmaps](uintptr_t) { ++unmaps; });
    uint8_t value = 0;
    Check(!mmio.ReadPhysicalMemory(0, &value, 1) &&
          mmio.last_status() == MmioStatus::InvalidArgument && unmaps == 1,
          "successful null mapping is rejected and released exactly once");
}

void TestCallbackFailureLifecycle()
{
    uint8_t value = 0;
    int unmaps = 0;
    Mmio throwingMap(nullptr,
        [](uint64_t, uintptr_t*, size_t) -> bool { throw std::runtime_error("map"); },
        [&unmaps](uintptr_t) { ++unmaps; });
    Check(!throwingMap.ReadPhysicalMemory(0, &value, 1) &&
          throwingMap.last_status() == MmioStatus::MappingFailed && unmaps == 0,
          "map callback exception is contained without inventing an unmap obligation");

    Mmio invalidMapping(nullptr,
        [](uint64_t, uintptr_t* out, size_t) { *out = UINTPTR_MAX - 0x10u; return true; },
        [&unmaps](uintptr_t) { ++unmaps; });
    Check(!invalidMapping.ReadPhysicalMemory(0, &value, 1) &&
          invalidMapping.last_status() == MmioStatus::InvalidArgument && unmaps == 1,
          "overflowing successful map is rejected and released exactly once");

    unmaps = 0;
    Mmio faultingMapping(nullptr,
        [](uint64_t, uintptr_t* out, size_t) { *out = 1; return true; },
        [&unmaps](uintptr_t) { ++unmaps; });
    Check(!faultingMapping.ReadPhysicalMemory(0, &value, 1) &&
          faultingMapping.last_status() == MmioStatus::InternalError && unmaps == 1,
          "fault during mapped copy is contained and released exactly once");

    uint8_t page[0x1000]{};
    page[0] = 0x5A;
    unmaps = 0;
    Mmio throwingUnmap(nullptr,
        [&page](uint64_t, uintptr_t* out, size_t size) {
            if (size != sizeof(page)) return false;
            *out = reinterpret_cast<uintptr_t>(page);
            return true;
        },
        [&unmaps](uintptr_t) { ++unmaps; throw std::runtime_error("unmap"); });
    Check(throwingUnmap.ReadPhysicalMemory(0, &value, 1) && value == 0x5A &&
          throwingUnmap.last_status() == MmioStatus::Ok && unmaps == 1,
          "unmap callback exception is contained after exactly one cleanup attempt");
}

void TestMoveAssignmentTransfersCallbacks()
{
    uint8_t physicalPage[0x1000]{};
    physicalPage[0] = 0x5A;
    int unmaps = 0;
    Mmio source(nullptr,
        [&physicalPage](uint64_t, uintptr_t* out, size_t size) {
            if (size != sizeof(physicalPage)) return false;
            *out = reinterpret_cast<uintptr_t>(physicalPage);
            return true;
        },
        [&unmaps](uintptr_t) { ++unmaps; });
    Mmio target(nullptr, [](uint64_t, uintptr_t*, size_t) { return false; }, [](uintptr_t) {});
    target = std::move(source);
    uint8_t value = 0;
    Check(target.ReadPhysicalMemory(0, &value, 1) && value == 0x5A && unmaps == 1,
          "move assignment transfers mapping callbacks and one cleanup obligation");
    uint8_t discarded = 0;
    Check(!source.ReadPhysicalMemory(0, &discarded, 1) &&
          source.last_status() == MmioStatus::BadCallbacks,
          "moved-from object clears callbacks and cannot create mappings");
}

void TestDetailedPartialOperations()
{
    constexpr uint64_t va = 0xFFFF800000001FF0ull;
    MockPhysicalMemory memory;
    memory.Put(0x1000 + Index(va, 39) * 8, 0x2000 | 3);
    memory.Put(0x2000 + Index(va, 30) * 8, 0x3000 | 3);
    memory.Put(0x3000 + Index(va, 21) * 8, 0x4000 | 3);
    memory.Put(0x4000 + Index(va, 12) * 8, 0xA000 | 3);
    uint8_t initial[16];
    for (size_t i = 0; i < sizeof(initial); ++i) initial[i] = static_cast<uint8_t>(0x20 + i);
    memory.PutBytes(0xAFF0, initial, sizeof(initial));

    Mmio mmio(nullptr,
        [&memory](uint64_t pa, uintptr_t* out, size_t size) { return memory.Map(pa, out, size); },
        [&memory](uintptr_t address) { memory.Unmap(address); });
    uint8_t readBuffer[32]{};
    const IoResult read = mmio.ReadKernelMemoryDetailed(
        va, readBuffer, sizeof(readBuffer), 0x1000, mmio_model::PagingMode::FourLevel);
    Check(read.status == MmioStatus::TranslationFailed && read.bytes_completed == 16 &&
          std::memcmp(readBuffer, initial, sizeof(initial)) == 0,
          "detailed cross-page read reports the completed first page segment");

    uint8_t writeBuffer[32];
    for (size_t i = 0; i < sizeof(writeBuffer); ++i) writeBuffer[i] = static_cast<uint8_t>(0x80 + i);
    const IoResult write = mmio.WriteKernelMemoryDetailed(
        va, writeBuffer, sizeof(writeBuffer), 0x1000, mmio_model::PagingMode::FourLevel);
    uint8_t written[16]{};
    std::memcpy(written, memory.pages[0xA000].data() + 0xFF0, sizeof(written));
    Check(write.status == MmioStatus::TranslationFailed && write.bytes_completed == 16 &&
          std::memcmp(written, writeBuffer, sizeof(written)) == 0,
          "detailed cross-page write reports completed bytes without rollback");
}
}

int main()
{
    TestModelBackedTranslation();
    TestInvalidArgumentsAndMappingFailure();
    TestNullMappingIsReleased();
    TestCallbackFailureLifecycle();
    TestMoveAssignmentTransfersCallbacks();
    TestDetailedPartialOperations();
    return failures == 0 ? 0 : 1;
}
