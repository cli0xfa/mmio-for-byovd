#pragma once

#include <cstdint>
#include <limits>
#include <algorithm>
#include <vector>

namespace mmio_model {

enum class PagingMode : uint8_t { Unknown, FourLevel, FiveLevel };
enum class WalkError : uint8_t {
    None,
    UnsupportedMode,
    InvalidAddress,
    InvalidPhysicalWidth,
    NotPresent,
    ReservedBits,
    ReadFailure,
};

struct WalkResult {
    uint64_t physical_address = 0;
    WalkError error = WalkError::None;
    explicit operator bool() const noexcept { return error == WalkError::None; }
};

struct PhysicalRange { uint64_t base = 0; uint64_t length = 0; };

enum class RangeError : uint8_t { None, Empty, Invalid };

constexpr bool IsCanonical(uint64_t address, unsigned virtual_address_bits) noexcept
{
    if (virtual_address_bits < 2 || virtual_address_bits > 63) return false;
    const unsigned top_width = 64 - virtual_address_bits + 1;
    const uint64_t top = address >> (virtual_address_bits - 1);
    const uint64_t all_ones = (uint64_t{1} << top_width) - 1;
    return top == 0 || top == all_ones;
}

constexpr unsigned TopLevelIndex(uint64_t virtual_address, PagingMode mode) noexcept
{
    const unsigned shift = mode == PagingMode::FiveLevel ? 48u : 39u;
    return static_cast<unsigned>((virtual_address >> shift) & 0x1FFu);
}

constexpr bool IsValidRange(uint64_t address, uint64_t size) noexcept
{
    return size != 0 && size <= (std::numeric_limits<uint64_t>::max)() - address;
}

constexpr bool IsPhysicalRangeSupported(uint64_t address, uint64_t size,
                                        unsigned physical_address_bits) noexcept
{
    if (physical_address_bits < 12 || physical_address_bits > 52 ||
        !IsValidRange(address, size)) return false;
    const uint64_t limit = uint64_t{1} << physical_address_bits;
    return address < limit && size <= limit - address;
}

inline RangeError NormalizePhysicalRanges(std::vector<PhysicalRange>& ranges)
{
    if (ranges.empty()) return RangeError::Empty;
    for (const auto& range : ranges) {
        if (!IsValidRange(range.base, range.length) ||
            (range.base & 0xFFFu) != 0 || (range.length & 0xFFFu) != 0)
            return RangeError::Invalid;
    }
    std::sort(ranges.begin(), ranges.end(), [](const PhysicalRange& a, const PhysicalRange& b) {
        return a.base < b.base;
    });
    std::vector<PhysicalRange> merged;
    merged.reserve(ranges.size());
    for (const auto& range : ranges) {
        if (merged.empty()) { merged.push_back(range); continue; }
        auto& previous = merged.back();
        const uint64_t previous_end = previous.base + previous.length;
        if (range.base <= previous_end) {
            const uint64_t range_end = range.base + range.length;
            if (range_end > previous_end) previous.length = range_end - previous.base;
        } else {
            merged.push_back(range);
        }
    }
    ranges.swap(merged);
    return RangeError::None;
}

// Reader receives a physical address of one paging entry and returns false
// when that entry cannot be read. This keeps the page-table model independent
// from Windows and lets tests use synthetic physical memory.
template <typename ReadEntry>
WalkResult WalkPageTables(uint64_t virtual_address,
                         uint64_t cr3_physical_address,
                         unsigned physical_address_bits,
                         PagingMode mode,
                         ReadEntry&& read_entry)
{
    if (mode == PagingMode::Unknown)
        return {0, WalkError::UnsupportedMode};
    if (physical_address_bits < 12 || physical_address_bits > 52)
        return {0, WalkError::InvalidPhysicalWidth};

    const bool five_level = mode == PagingMode::FiveLevel;
    const unsigned va_bits = five_level ? 57u : 48u;
    if (!IsCanonical(virtual_address, va_bits))
        return {0, WalkError::InvalidAddress};

    const uint64_t physical_mask = ((uint64_t{1} << physical_address_bits) - 1) & ~uint64_t{0xFFF};
    constexpr uint64_t address_field_mask = 0x000FFFFFFFFFF000ull;
    constexpr uint64_t cr3_allowed_mask = address_field_mask | 0xFFFu;
    if ((cr3_physical_address & ~cr3_allowed_mask) != 0)
        return {0, WalkError::ReservedBits};
    if (((cr3_physical_address & address_field_mask) & ~physical_mask) != 0)
        return {0, WalkError::ReservedBits};
    constexpr uint64_t present_bit = 1;
    constexpr uint64_t large_page_bit = uint64_t{1} << 7;
    const unsigned shifts4[] = {39, 30, 21, 12};
    const unsigned shifts5[] = {48, 39, 30, 21, 12};
    const unsigned* shifts = five_level ? shifts5 : shifts4;
    const unsigned levels = five_level ? 5u : 4u;

    uint64_t table = cr3_physical_address & physical_mask;
    uint64_t entry = 0;
    for (unsigned level = 0; level < levels; ++level) {
        const unsigned shift = shifts[level];
        const uint64_t index = (virtual_address >> shift) & 0x1FFu;
        if (!read_entry(table + index * sizeof(uint64_t), entry))
            return {0, WalkError::ReadFailure};
        if ((entry & present_bit) == 0)
            return {0, WalkError::NotPresent};

        const uint64_t address_bits = entry & address_field_mask;
        if ((address_bits & ~physical_mask) != 0)
            return {0, WalkError::ReservedBits};

        if ((entry & large_page_bit) != 0 && shift != 12) {
            if (shift != 30 && shift != 21)
                return {0, WalkError::ReservedBits};
            // Bit 12 is the PAT selector for large pages, not part of the
            // page-frame address. Bits 13..(shift-1) must be zero.
            const uint64_t low_address_bits = ((uint64_t{1} << shift) - 1) &
                                              ~uint64_t{0x1FFF};
            if ((address_bits & low_address_bits) != 0)
                return {0, WalkError::ReservedBits};
            const uint64_t page_mask = physical_mask & ~((uint64_t{1} << shift) - 1);
            const uint64_t page_offset_mask = (uint64_t{1} << shift) - 1;
            return {(entry & page_mask) | (virtual_address & page_offset_mask), WalkError::None};
        }

        if (level + 1 == levels)
            return {(entry & physical_mask) | (virtual_address & 0xFFFu), WalkError::None};
        table = entry & physical_mask;
    }
    return {0, WalkError::ReadFailure};
}

} // namespace mmio_model
