// windowed_filter.hpp - rewrite of core/internal/congestion/bbr/windowed_filter.go.
// Implements Kathleen Nichols' algorithm for tracking the minimum (or maximum)
// estimate of a stream of samples over some fixed time interval. Keeps track
// of the best, second best and third best estimates; see the Go original for
// the full description.
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <utility>

namespace hy2::bbr {

// Compares two values and returns 1 if the first is greater than the second,
// -1 if it is less, and 0 if they are equal (Go: MaxFilter).
struct MaxFilter {
    template <typename O>
    constexpr int operator()(const O& a, const O& b) const {
        if (a > b) return 1;
        if (a < b) return -1;
        return 0;
    }
};

// Compares two values and returns 1 if the first is less than the second,
// -1 if it is greater, and 0 if they are equal (Go: MinFilter).
struct MinFilter {
    template <typename O>
    constexpr int operator()(const O& a, const O& b) const {
        if (a < b) return 1;
        if (a > b) return -1;
        return 0;
    }
};

template <typename V, typename T>
class WindowedFilter {
public:
    using Comparator = std::function<int(const V&, const V&)>;

    WindowedFilter(T windowLength, Comparator comparator)
        : windowLength_(windowLength), comparator_(std::move(comparator)) {}

    // Changes the window length. Does not update any current samples.
    void SetWindowLength(T windowLength) { windowLength_ = windowLength; }

    const V& GetBest() const { return estimates_[0].sample; }
    const V& GetSecondBest() const { return estimates_[1].sample; }
    const V& GetThirdBest() const { return estimates_[2].sample; }

    // Updates best estimates with |newSample|, and expires and updates best
    // estimates as necessary.
    void Update(const V& newSample, T newTime) {
        static const V kZero{};
        // Reset all estimates if they have not yet been initialized, if new
        // sample is a new best, or if the newest recorded estimate is too old.
        if (comparator_(estimates_[0].sample, kZero) == 0 ||
            comparator_(newSample, estimates_[0].sample) >= 0 ||
            newTime - estimates_[2].time > windowLength_) {
            Reset(newSample, newTime);
            return;
        }

        if (comparator_(newSample, estimates_[1].sample) >= 0) {
            estimates_[1] = Entry{newSample, newTime};
            estimates_[2] = estimates_[1];
        } else if (comparator_(newSample, estimates_[2].sample) >= 0) {
            estimates_[2] = Entry{newSample, newTime};
        }

        // Expire and update estimates as necessary.
        if (newTime - estimates_[0].time > windowLength_) {
            // The best estimate hasn't been updated for an entire window, so
            // promote second and third best estimates.
            estimates_[0] = estimates_[1];
            estimates_[1] = estimates_[2];
            estimates_[2] = Entry{newSample, newTime};
            // Need to iterate one more time. Check if the new best estimate is
            // outside the window as well, since it may also have been recorded
            // a long time ago.
            if (newTime - estimates_[0].time > windowLength_) {
                estimates_[0] = estimates_[1];
                estimates_[1] = estimates_[2];
            }
            return;
        }
        if (comparator_(estimates_[1].sample, estimates_[0].sample) == 0 &&
            newTime - estimates_[1].time > windowLength_ / 4) {
            // A quarter of the window has passed without a better sample, so
            // the second-best estimate is taken from the second quarter of the
            // window.
            estimates_[1] = Entry{newSample, newTime};
            estimates_[2] = estimates_[1];
            return;
        }

        if (comparator_(estimates_[2].sample, estimates_[1].sample) == 0 &&
            newTime - estimates_[2].time > windowLength_ / 2) {
            // We've passed a half of the window without a better estimate, so
            // take a third-best estimate from the second half of the window.
            estimates_[2] = Entry{newSample, newTime};
        }
    }

    // Resets all estimates to new sample.
    void Reset(const V& newSample, T newTime) {
        estimates_[2] = Entry{newSample, newTime};
        estimates_[1] = estimates_[2];
        estimates_[0] = estimates_[1];
    }

    void Clear() { estimates_.fill(Entry{}); }

private:
    struct Entry {
        V sample{};
        T time{};
    };

    // Time length of window.
    T windowLength_;
    std::array<Entry, 3> estimates_{};
    Comparator comparator_;
};

} // namespace hy2::bbr
