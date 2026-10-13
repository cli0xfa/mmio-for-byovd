#define MMIO_MODEL_ONLY
#include "../mmio-for-byovd/mmio.hpp"
#undef MMIO_MODEL_ONLY

#include <cstdlib>
#include <iostream>
#include <unordered_map>
#include <vector>

using mmio_model::PagingMode;
using mmio_model::WalkError;

namespace {
int failures = 0;
void Check(bool condition, const char* name)
{
    if (condition) std::cout << "[PASS] " << name << '\n';
    else { std::cerr << "[FAIL] " << name << '\n'; ++failures; }
}

struct PageTables {
    std::unordered_map<uint64_t, uint64_t> entries;
    bool Read(uint64_t pa, uint64_t& value) const
    {
        const auto it = entries.find(pa);
        if (it == entries.end()) return false;
        value = it->second;
        return true;
    }
    void Put(uint64_t table, uint64_t index, uint64_t value)
    {
        entries[table + index * 8] = value;
    }
};

uint64_t Index(uint64_t va, unsigned shift) { return (va >> shift) & 0x1ff; }
constexpr uint64_t kPresent = 1;
constexpr uint64_t kWritable = 2;
constexpr uint64_t kLarge = 1ull << 7;
constexpr uint64_t kLargePagePat = 1ull << 12;

void TestFourLevel4K()
{
    constexpr uint64_t va = 0xffff800012345678ull;
    PageTables m;
    m.Put(0x1000, Index(va, 39), 0x2000 | kPresent | kWritable);
    m.Put(0x2000, Index(va, 30), 0x3000 | kPresent | kWritable);
    m.Put(0x3000, Index(va, 21), 0x4000 | kPresent | kWritable);
    m.Put(0x4000, Index(va, 12), 0xABCDE000 | kPresent | kWritable | kLarge); // PTE PAT bit
    const auto result = mmio_model::WalkPageTables(va, 0x1000, 48, PagingMode::FourLevel,
        [&m](uint64_t pa, uint64_t& value) { return m.Read(pa, value); });
    Check(result && result.physical_address == 0xABCDE678, "4-level 4 KB translation");
}

void TestFiveLevel4K()
{
    constexpr uint64_t va = 0xff123456789abcdeull;
    PageTables m;
    m.Put(0x1000, Index(va, 48), 0x2000 | kPresent);
    m.Put(0x2000, Index(va, 39), 0x3000 | kPresent);
    m.Put(0x3000, Index(va, 30), 0x4000 | kPresent);
    m.Put(0x4000, Index(va, 21), 0x5000 | kPresent);
    m.Put(0x5000, Index(va, 12), 0xABCDE000 | kPresent);
    const auto result = mmio_model::WalkPageTables(va, 0x1000, 48, PagingMode::FiveLevel,
        [&m](uint64_t pa, uint64_t& value) { return m.Read(pa, value); });
    Check(result && result.physical_address == (0xABCDE000 | (va & 0xfff)), "5-level 4 KB translation");
}

void TestLargePages()
{
    constexpr uint64_t va2m = 0xffff800012345678ull;
    PageTables m2;
    m2.Put(0x1000, Index(va2m, 39), 0x2000 | kPresent);
    m2.Put(0x2000, Index(va2m, 30), 0x3000 | kPresent);
    m2.Put(0x3000, Index(va2m, 21), 0x800000 | kPresent | kLarge | kLargePagePat);
    auto r2 = mmio_model::WalkPageTables(va2m, 0x1000, 48, PagingMode::FourLevel,
        [&m2](uint64_t pa, uint64_t& value) { return m2.Read(pa, value); });
    Check(r2 && r2.physical_address == (0x800000 | (va2m & 0x1fffff)), "2 MB large-page translation");

    constexpr uint64_t va1g = 0xffff800012345678ull;
    PageTables m1;
    m1.Put(0x1000, Index(va1g, 39), 0x2000 | kPresent);
    m1.Put(0x2000, Index(va1g, 30), 0x40000000 | kPresent | kLarge | kLargePagePat);
    auto r1 = mmio_model::WalkPageTables(va1g, 0x1000, 48, PagingMode::FourLevel,
        [&m1](uint64_t pa, uint64_t& value) { return m1.Read(pa, value); });
    Check(r1 && r1.physical_address == (0x40000000 | (va1g & 0x3fffffff)), "1 GB large-page translation");

    constexpr uint64_t va5 = 0xff123456789abcdeull;
    PageTables m5_2m;
    m5_2m.Put(0x1000, Index(va5, 48), 0x2000 | kPresent);
    m5_2m.Put(0x2000, Index(va5, 39), 0x3000 | kPresent);
    m5_2m.Put(0x3000, Index(va5, 30), 0x4000 | kPresent);
    m5_2m.Put(0x4000, Index(va5, 21), 0x200000 | kPresent | kLarge | kLargePagePat);
    auto r5_2m = mmio_model::WalkPageTables(va5, 0x1000, 48, PagingMode::FiveLevel,
        [&m5_2m](uint64_t pa, uint64_t& value) { return m5_2m.Read(pa, value); });
    Check(r5_2m && r5_2m.physical_address == (0x200000 | (va5 & 0x1fffff)),
          "5-level 2 MB large-page translation");

    PageTables m5_1g;
    m5_1g.Put(0x1000, Index(va5, 48), 0x2000 | kPresent);
    m5_1g.Put(0x2000, Index(va5, 39), 0x3000 | kPresent);
    m5_1g.Put(0x3000, Index(va5, 30), 0x80000000 | kPresent | kLarge | kLargePagePat);
    auto r5_1g = mmio_model::WalkPageTables(va5, 0x1000, 48, PagingMode::FiveLevel,
        [&m5_1g](uint64_t pa, uint64_t& value) { return m5_1g.Read(pa, value); });
    Check(r5_1g && r5_1g.physical_address == (0x80000000 | (va5 & 0x3fffffff)),
          "5-level 1 GB large-page translation");
}

void TestFailuresAndBoundaries()
{
    PageTables empty;
    auto unknown = mmio_model::WalkPageTables(0xffff800000000000ull, 0x1000, 48, PagingMode::Unknown,
        [&empty](uint64_t pa, uint64_t& value) { return empty.Read(pa, value); });
    Check(unknown.error == WalkError::UnsupportedMode, "unknown mode is reported explicitly");

    auto noncanonical = mmio_model::WalkPageTables(0x0000800000000000ull, 0x1000, 48, PagingMode::FourLevel,
        [&empty](uint64_t pa, uint64_t& value) { return empty.Read(pa, value); });
    Check(noncanonical.error == WalkError::InvalidAddress, "non-canonical address rejected");

    PageTables missing;
    missing.Put(0x1000, Index(0xffff800000000000ull, 39), 0x2000 | kPresent);
    auto absent = mmio_model::WalkPageTables(0xffff800000000000ull, 0x1000, 48, PagingMode::FourLevel,
        [&missing](uint64_t pa, uint64_t& value) { return missing.Read(pa, value); });
    Check(absent.error == WalkError::ReadFailure, "missing next-level entry read rejected");

    PageTables not_present;
    not_present.Put(0x1000, Index(0xffff800000000000ull, 39), 0x2000);
    auto absent_flag = mmio_model::WalkPageTables(0xffff800000000000ull, 0x1000, 48, PagingMode::FourLevel,
        [&not_present](uint64_t pa, uint64_t& value) { return not_present.Read(pa, value); });
    Check(absent_flag.error == WalkError::NotPresent, "non-present entry rejected");

    PageTables reserved;
    reserved.Put(0x1000, Index(0xffff800000000000ull, 39), 0x2000 | kPresent | kLarge);
    auto bad_ps = mmio_model::WalkPageTables(0xffff800000000000ull, 0x1000, 48, PagingMode::FourLevel,
        [&reserved](uint64_t pa, uint64_t& value) { return reserved.Read(pa, value); });
    Check(bad_ps.error == WalkError::ReservedBits, "large-page bit at PML4 rejected");

    PageTables misaligned_large;
    misaligned_large.Put(0x1000, Index(0xffff800000000000ull, 39), 0x2000 | kPresent);
    misaligned_large.Put(0x2000, Index(0xffff800000000000ull, 30), 0x3000 | kPresent);
    misaligned_large.Put(0x3000, Index(0xffff800000000000ull, 21), 0x802000 | kPresent | kLarge);
    auto bad_large_alignment = mmio_model::WalkPageTables(0xffff800000000000ull, 0x1000, 48,
        PagingMode::FourLevel, [&misaligned_large](uint64_t pa, uint64_t& value) {
            return misaligned_large.Read(pa, value);
        });
    Check(bad_large_alignment.error == WalkError::ReservedBits,
          "reserved low address bits in a 2 MB entry rejected");

    PageTables over_width;
    over_width.Put(0x1000, Index(0xffff800000000000ull, 39), 0x2000 | kPresent);
    over_width.Put(0x2000, Index(0xffff800000000000ull, 30), 0x3000 | kPresent);
    over_width.Put(0x3000, Index(0xffff800000000000ull, 21), 0x4000 | kPresent);
    over_width.Put(0x4000, Index(0xffff800000000000ull, 12), (1ull << 48) | kPresent);
    auto bad_pte_width = mmio_model::WalkPageTables(0xffff800000000000ull, 0x1000, 48,
        PagingMode::FourLevel, [&over_width](uint64_t pa, uint64_t& value) { return over_width.Read(pa, value); });
    Check(bad_pte_width.error == WalkError::ReservedBits,
          "PTE address bits above MAXPHYADDR rejected");

    Check(!mmio_model::IsValidRange(UINT64_MAX, 1), "range ending past UINT64_MAX rejected");
    Check(!mmio_model::IsValidRange(0, 0), "zero-length range rejected");
    Check(mmio_model::IsValidRange(0, 1), "range beginning at zero is valid");
    Check(mmio_model::IsValidRange(UINT64_MAX - 1, 1), "last representable non-overflowing range accepted");
    Check(mmio_model::IsPhysicalRangeSupported(0, 1ull << 48, 48) &&
          !mmio_model::IsPhysicalRangeSupported(0, 1ull << 48, 47),
          "physical ranges are bounded by MAXPHYADDR");

    constexpr uint64_t shared_high_half = 0xffff800000000000ull;
    constexpr uint64_t la57_only = 0xff10000000000000ull;
    Check(mmio_model::IsCanonical(shared_high_half, 48) && mmio_model::IsCanonical(shared_high_half, 57),
          "shared high-half address is ambiguous by canonicality alone");
    Check(mmio_model::IsCanonical(la57_only, 57) && !mmio_model::IsCanonical(la57_only, 48),
          "LA57-exclusive address identifies five-level canonicality");
    Check(mmio_model::TopLevelIndex(shared_high_half, PagingMode::FourLevel) == 0x100 &&
          mmio_model::TopLevelIndex(shared_high_half, PagingMode::FiveLevel) == 0x1FF &&
          mmio_model::TopLevelIndex(la57_only, PagingMode::FiveLevel) == 0x110,
          "top-level candidate index follows the virtual address in both modes");

    PageTables bad_cr3;
    auto reserved_cr3 = mmio_model::WalkPageTables(0xffff800000000000ull, 0x1000000000000ull, 48,
        PagingMode::FourLevel, [&bad_cr3](uint64_t pa, uint64_t& value) { return bad_cr3.Read(pa, value); });
    Check(reserved_cr3.error == WalkError::ReservedBits, "CR3 bits above MAXPHYADDR rejected");
    auto reserved_high_cr3 = mmio_model::WalkPageTables(0xffff800000000000ull,
        0x8000000000001000ull, 48, PagingMode::FourLevel,
        [&bad_cr3](uint64_t pa, uint64_t& value) { return bad_cr3.Read(pa, value); });
    Check(reserved_high_cr3.error == WalkError::ReservedBits,
          "reserved high CR3 bits outside the physical address field rejected");

    std::vector<mmio_model::PhysicalRange> ranges{{0x4000, 0x2000}, {0x1000, 0x3000}, {0x6000, 0x1000}};
    const auto rangeResult = mmio_model::NormalizePhysicalRanges(ranges);
    Check(rangeResult == mmio_model::RangeError::None && ranges.size() == 1 &&
          ranges[0].base == 0x1000 && ranges[0].length == 0x6000,
          "physical ranges are sorted and overlapping ranges merged");

    std::vector<mmio_model::PhysicalRange> badRanges{{0x1001, 0x1000}};
    Check(mmio_model::NormalizePhysicalRanges(badRanges) == mmio_model::RangeError::Invalid,
          "unaligned physical range rejected");
}
}

int main()
{
    TestFourLevel4K();
    TestFiveLevel4K();
    TestLargePages();
    TestFailuresAndBoundaries();
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
