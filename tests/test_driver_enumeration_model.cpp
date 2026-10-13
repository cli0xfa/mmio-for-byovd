#define MMIO_MODEL_ONLY
#include "../mmio-for-byovd/mmio.hpp"
#undef MMIO_MODEL_ONLY

#include <cstdlib>
#include <iostream>
#include <limits>
#include <vector>

namespace {
int failures = 0;
void Check(bool condition, const char* name)
{
	if (condition) std::cout << "[PASS] " << name << '\n';
	else { std::cerr << "[FAIL] " << name << '\n'; ++failures; }
}

using mmio_model::EnumerationCall;
using mmio_model::EnumerationCallStatus;
using mmio_model::EnumerationError;

void TestGrowingEnumeration()
{
	int calls = 0;
	const auto result = mmio_model::CollectEnumeration<int>([&calls](int* entries, size_t capacity) {
		++calls;
		if (capacity == 0)
			return EnumerationCall{EnumerationCallStatus::InsufficientBuffer, 2 * sizeof(int), 122};
		if (capacity == 2 * sizeof(int))
			return EnumerationCall{EnumerationCallStatus::InsufficientBuffer, 4 * sizeof(int), 122};
		if (capacity == 4 * sizeof(int)) {
			entries[0] = 11; entries[1] = 22; entries[2] = 33; entries[3] = 44;
			return EnumerationCall{EnumerationCallStatus::Success, 4 * sizeof(int), 0};
		}
		return EnumerationCall{EnumerationCallStatus::Failure, 0, 87};
	});
	Check(result && calls == 3 && result.entries == std::vector<int>{11, 22, 33, 44},
	      "growing enumeration retries with the reported aligned capacity");
}

void TestIncompleteAndMalformedResults()
{
	int calls = 0;
	const auto incomplete = mmio_model::CollectEnumeration<int>([&calls](int* entries, size_t capacity) {
		++calls;
		if (capacity == 0)
			return EnumerationCall{EnumerationCallStatus::Success, 2 * sizeof(int), 0};
		if (capacity == 2 * sizeof(int))
			return EnumerationCall{EnumerationCallStatus::Success, 3 * sizeof(int), 0};
		entries[0] = 1; entries[1] = 2; entries[2] = 3;
		return EnumerationCall{EnumerationCallStatus::Success, 3 * sizeof(int), 0};
	});
	Check(incomplete && calls == 3 && incomplete.entries == std::vector<int>{1, 2, 3},
	      "successful but incomplete report is retried before entries are exposed");

	const auto shrinking = mmio_model::CollectEnumeration<int>([](int* entries, size_t capacity) {
		if (capacity == 0)
			return EnumerationCall{EnumerationCallStatus::Success, 4 * sizeof(int), 0};
		entries[0] = 7;
		entries[1] = 8;
		return EnumerationCall{EnumerationCallStatus::Success, 2 * sizeof(int), 0};
	});
	Check(shrinking && shrinking.entries == std::vector<int>{7, 8},
	      "a list that shrinks between query and data call exposes only returned entries");

	const auto partial = mmio_model::CollectEnumeration<int>([](int*, size_t) {
		return EnumerationCall{EnumerationCallStatus::Success, sizeof(int) + 1, 0};
	});
	Check(partial.error == EnumerationError::InvalidLength,
	      "non-integral entry lengths are rejected rather than truncated");

	const auto empty = mmio_model::CollectEnumeration<int>([](int*, size_t) {
		return EnumerationCall{EnumerationCallStatus::Success, 0, 0};
	});
	Check(empty.error == EnumerationError::Empty, "zero-entry enumeration is reported explicitly");
}

void TestEnumerationFailures()
{
	const auto apiFailure = mmio_model::CollectEnumeration<int>([](int*, size_t) {
		return EnumerationCall{EnumerationCallStatus::Failure, 0, 5};
	});
	Check(apiFailure.error == EnumerationError::ApiFailure && apiFailure.os_error == 5,
	      "API failure preserves its OS error code");

	int failedDataCalls = 0;
	const auto dataFailure = mmio_model::CollectEnumeration<int>([&failedDataCalls](int*, size_t capacity) {
		if (capacity == 0)
			return EnumerationCall{EnumerationCallStatus::InsufficientBuffer, 2 * sizeof(int), 122};
		++failedDataCalls;
		return EnumerationCall{EnumerationCallStatus::Failure, 0, 5};
	});
	Check(dataFailure.error == EnumerationError::ApiFailure && dataFailure.os_error == 5 &&
	      failedDataCalls == 1,
	      "data-call API failure preserves its OS error and stops enumeration");

	int calls = 0;
	const auto unstable = mmio_model::CollectEnumeration<int>([&calls](int*, size_t capacity) {
		++calls;
		if (capacity == 0)
			return EnumerationCall{EnumerationCallStatus::InsufficientBuffer, 2 * sizeof(int), 122};
		return EnumerationCall{EnumerationCallStatus::InsufficientBuffer, 2 * sizeof(int), 122};
	});
	Check(unstable.error == EnumerationError::Unstable && calls == 2,
	      "non-growing insufficient-buffer result fails without a useless retry loop");

	int growingCalls = 0;
	const auto keepsGrowing = mmio_model::CollectEnumeration<int>([&growingCalls](int*, size_t capacity) {
		++growingCalls;
		const size_t bytes = capacity == 0 ? 2 * sizeof(int) : capacity + sizeof(int);
		return EnumerationCall{EnumerationCallStatus::InsufficientBuffer, bytes, 122};
	});
	Check(keepsGrowing.error == EnumerationError::Unstable && growingCalls == 4,
	      "repeatedly changing enumeration size stops at the retry limit");

	const size_t maxAligned = (std::numeric_limits<size_t>::max)() -
	                          (std::numeric_limits<size_t>::max)() % sizeof(int);
	const auto tooLarge = mmio_model::CollectEnumeration<int>([maxAligned](int*, size_t) {
		return EnumerationCall{EnumerationCallStatus::Success, maxAligned, 0};
	});
	Check((tooLarge.error == EnumerationError::InvalidLength ||
	       tooLarge.error == EnumerationError::AllocationFailure) && tooLarge.entries.empty(),
	      "extreme enumeration capacity fails cleanly without exposing a partial list");
}

void TestUniqueKernelSelection()
{
	const std::vector<int> reordered{0, 1, 2, 3};
	const auto unique = mmio_model::SelectUniqueMatch(reordered,
		[](size_t index) { return index == 2; });
	Check(unique.selection == mmio_model::MatchSelection::Unique && unique.index == 2,
	      "unique kernel match is selected independently of list order");

	const auto missing = mmio_model::SelectUniqueMatch(reordered,
		[](size_t) { return false; });
	Check(missing.selection == mmio_model::MatchSelection::None,
	      "no recognized kernel image is a distinct result");

	const auto ambiguous = mmio_model::SelectUniqueMatch(reordered,
		[](size_t index) { return index == 1 || index == 3; });
	Check(ambiguous.selection == mmio_model::MatchSelection::Ambiguous,
	      "multiple recognized kernel images are rejected as ambiguous");
}
}

int main()
{
	TestGrowingEnumeration();
	TestIncompleteAndMalformedResults();
	TestEnumerationFailures();
	TestUniqueKernelSelection();
	return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
