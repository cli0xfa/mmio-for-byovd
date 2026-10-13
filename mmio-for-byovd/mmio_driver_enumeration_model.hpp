#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <utility>
#include <vector>

namespace mmio_model {

enum class EnumerationCallStatus : uint8_t { Success, InsufficientBuffer, Failure };

struct EnumerationCall {
	EnumerationCallStatus status = EnumerationCallStatus::Failure;
	size_t reported_bytes = 0;
	uint32_t os_error = 0;
};

enum class EnumerationError : uint8_t {
	None,
	ApiFailure,
	Empty,
	InvalidLength,
	Unstable,
	AllocationFailure,
};

template <typename Entry>
struct EnumerationResult {
	std::vector<Entry> entries;
	EnumerationError error = EnumerationError::None;
	uint32_t os_error = 0;
	explicit operator bool() const noexcept { return error == EnumerationError::None; }
};

// The callback mirrors size-query APIs: pass nullptr/0 first, then a buffer
// and its byte capacity. reported_bytes is the API's required/returned size.
// An insufficient-buffer result is retried only when it reports a strictly
// larger, entry-aligned size. Successful but incomplete reports are also
// retried, and never exposed as a complete result.
template <typename Entry, typename Enumerate>
EnumerationResult<Entry> CollectEnumeration(Enumerate&& enumerate, size_t max_attempts = 3)
{
	const EnumerationCall query = enumerate(nullptr, 0);
	if (query.status == EnumerationCallStatus::Failure)
		return {{}, EnumerationError::ApiFailure, query.os_error};
	if (query.reported_bytes == 0)
		return {{}, EnumerationError::Empty, query.os_error};
	if (query.reported_bytes % sizeof(Entry) != 0)
		return {{}, EnumerationError::InvalidLength, query.os_error};
	if (max_attempts == 0)
		return {{}, EnumerationError::Unstable, query.os_error};

	size_t required_bytes = query.reported_bytes;
	for (size_t attempt = 0; attempt < max_attempts; ++attempt) {
		if (required_bytes % sizeof(Entry) != 0)
			return {{}, EnumerationError::InvalidLength, query.os_error};
		const size_t count = required_bytes / sizeof(Entry);
		std::vector<Entry> entries;
		if (count > entries.max_size())
			return {{}, EnumerationError::InvalidLength, query.os_error};
		try {
			entries.resize(count);
		} catch (...) {
			return {{}, EnumerationError::AllocationFailure, 0};
		}
		const size_t capacity_bytes = count * sizeof(Entry);
		const EnumerationCall call = enumerate(entries.data(), capacity_bytes);
		if (call.status == EnumerationCallStatus::Failure)
			return {{}, EnumerationError::ApiFailure, call.os_error};
		if (call.reported_bytes == 0)
			return {{}, EnumerationError::Empty, call.os_error};
		if (call.reported_bytes % sizeof(Entry) != 0)
			return {{}, EnumerationError::InvalidLength, call.os_error};

		if (call.reported_bytes > capacity_bytes) {
			if (attempt + 1 == max_attempts)
				return {{}, EnumerationError::Unstable, call.os_error};
			required_bytes = call.reported_bytes;
			continue;
		}
		if (call.status == EnumerationCallStatus::InsufficientBuffer) {
			// The reported size did not grow despite an insufficient-buffer
			// response, so another allocation with the same capacity cannot help.
			return {{}, EnumerationError::Unstable, call.os_error};
		}

		entries.resize(call.reported_bytes / sizeof(Entry));
		return {std::move(entries), EnumerationError::None, call.os_error};
	}
	return {{}, EnumerationError::Unstable, query.os_error};
}

enum class MatchSelection : uint8_t { None, Unique, Ambiguous };

struct UniqueMatchResult {
	MatchSelection selection = MatchSelection::None;
	size_t index = (std::numeric_limits<size_t>::max)();
};

template <typename Range, typename Predicate>
UniqueMatchResult SelectUniqueMatch(const Range& range, Predicate&& matches)
{
	UniqueMatchResult result;
	for (size_t i = 0; i < range.size(); ++i) {
		if (!matches(i)) continue;
		if (result.selection == MatchSelection::Unique) {
			result.selection = MatchSelection::Ambiguous;
			result.index = (std::numeric_limits<size_t>::max)();
			return result;
		}
		result.selection = MatchSelection::Unique;
		result.index = i;
	}
	return result;
}

} // namespace mmio_model
