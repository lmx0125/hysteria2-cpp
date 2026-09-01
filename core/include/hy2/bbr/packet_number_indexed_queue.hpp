// packet_number_indexed_queue.hpp - rewrite of
// core/internal/congestion/bbr/packet_number_indexed_queue.go.
#pragma once

#include <cstddef>
#include <functional>

#include "hy2/common.hpp"
#include "hy2/bbr/ringbuffer.hpp"

namespace hy2::bbr {

constexpr PacketNumber kInvalidPacketNumber = -1;

// PacketNumberIndexedQueue is a queue of mostly continuous numbered entries
// which supports the following operations:
// - adding elements to the end of the queue, or at some point past the end
// - removing elements in any order
// - retrieving elements
// If all elements are inserted in order, all of the operations above are
// amortized O(1) time.
template <typename T>
class PacketNumberIndexedQueue {
public:
    explicit PacketNumberIndexedQueue(std::size_t size) { entries_.Init(size); }

    // Inserts data associated with |packetNumber| into (or past) the end of the
    // queue, filling up missing intermediate entries as necessary. Returns true
    // if the element has been inserted successfully, false if it was already in
    // the queue or inserted out of order (mirrors Go's nil-entry check).
    bool Emplace(PacketNumber packetNumber, const T* entry) {
        if (packetNumber == kInvalidPacketNumber || entry == nullptr) {
            return false;
        }

        if (IsEmpty()) {
            entries_.PushBack(EntryWrapper{true, *entry});
            numberOfPresentEntries_ = 1;
            firstPacket_ = packetNumber;
            return true;
        }

        // Do not allow insertion out-of-order.
        if (packetNumber <= LastPacket()) {
            return false;
        }

        // Handle potentially missing elements.
        std::int64_t offset = packetNumber - firstPacket_;
        std::int64_t gap = offset - static_cast<std::int64_t>(entries_.Len());
        if (gap > 0) {
            for (std::int64_t i = 0; i < gap; i++) {
                entries_.PushBack(EntryWrapper{});
            }
        }

        entries_.PushBack(EntryWrapper{true, *entry});
        numberOfPresentEntries_++;
        return true;
    }

    // Retrieves the entry associated with the packet number. Returns nullptr if
    // the entry does not exist.
    T* GetEntry(PacketNumber packetNumber) {
        EntryWrapper* ew = getEntryWrapper(packetNumber);
        if (ew == nullptr) {
            return nullptr;
        }
        return &ew->entry;
    }
    const T* GetEntry(PacketNumber packetNumber) const {
        const EntryWrapper* ew = getEntryWrapper(packetNumber);
        if (ew == nullptr) {
            return nullptr;
        }
        return &ew->entry;
    }

    // Same as removing an entry, but if an entry is present in the queue, also
    // calls f(entry) before removing it.
    bool Remove(PacketNumber packetNumber, const std::function<void(T&)>& f) {
        EntryWrapper* ew = getEntryWrapper(packetNumber);
        if (ew == nullptr) {
            return false;
        }
        if (f) {
            f(ew->entry);
        }
        ew->present = false;
        numberOfPresentEntries_--;

        if (packetNumber == FirstPacket()) {
            clearup();
        }

        return true;
    }

    // Removes all entries older than |packetNumber| ("up to", but not
    // including, |packetNumber|). Unused slots in the front are also removed,
    // which means when the function returns, FirstPacket() can be larger than
    // |packetNumber|.
    void RemoveUpTo(PacketNumber packetNumber) {
        while (!entries_.Empty() && firstPacket_ != kInvalidPacketNumber &&
               firstPacket_ < packetNumber) {
            if (entries_.Front()->present) {
                numberOfPresentEntries_--;
            }
            entries_.PopFront();
            firstPacket_++;
        }
        clearup();
    }

    bool IsEmpty() const { return numberOfPresentEntries_ == 0; }

    int NumberOfPresentEntries() const { return numberOfPresentEntries_; }

    // Number of entries allocated in the underlying deque; proportional to the
    // memory usage of the queue.
    int EntrySlotsUsed() const { return static_cast<int>(entries_.Len()); }

    PacketNumber FirstPacket() const { return firstPacket_; }

    // Packet number of the last entry ever inserted in the queue. Note that the
    // entry in question may have already been removed.
    PacketNumber LastPacket() const {
        if (IsEmpty()) {
            return kInvalidPacketNumber;
        }
        return firstPacket_ + static_cast<PacketNumber>(entries_.Len() - 1);
    }

private:
    struct EntryWrapper {
        bool present = false;
        T entry{};
    };

    EntryWrapper* getEntryWrapper(PacketNumber packetNumber) {
        return const_cast<EntryWrapper*>(
            static_cast<const PacketNumberIndexedQueue*>(this)->getEntryWrapper(packetNumber));
    }
    const EntryWrapper* getEntryWrapper(PacketNumber packetNumber) const {
        if (packetNumber == kInvalidPacketNumber || IsEmpty() || packetNumber < firstPacket_) {
            return nullptr;
        }

        auto offset = static_cast<std::size_t>(packetNumber - firstPacket_);
        if (offset >= entries_.Len()) {
            return nullptr;
        }

        const EntryWrapper* ew = entries_.Offset(offset);
        if (ew == nullptr || !ew->present) {
            return nullptr;
        }

        return ew;
    }

    void clearup() {
        while (!entries_.Empty() && !entries_.Front()->present) {
            entries_.PopFront();
            firstPacket_++;
        }
        if (entries_.Empty()) {
            firstPacket_ = kInvalidPacketNumber;
        }
    }

    RingBuffer<EntryWrapper> entries_;
    int numberOfPresentEntries_ = 0;
    PacketNumber firstPacket_ = kInvalidPacketNumber;
};

} // namespace hy2::bbr
