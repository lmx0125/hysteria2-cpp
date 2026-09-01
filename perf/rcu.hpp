// rcu.hpp - RCU 读拷贝更新机制 (MSVC 兼容)
#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace hy2::perf {

// ---------------------------------------------------------------------------
// RCUAccessor<T> - 读取侧 RAII 守卫
// ---------------------------------------------------------------------------
template <typename T>
class RCUAccessor {
    std::shared_ptr<const T> ptr_;
public:
    explicit RCUAccessor(std::shared_ptr<const T> p) noexcept : ptr_(static_cast<std::shared_ptr<const T>&&>(p)) {}
    RCUAccessor(RCUAccessor&& o) noexcept : ptr_(static_cast<std::shared_ptr<const T>&&>(o.ptr_)) {}
    RCUAccessor& operator=(RCUAccessor&& o) noexcept { ptr_ = static_cast<std::shared_ptr<const T>&&>(o.ptr_); return *this; }
    RCUAccessor(const RCUAccessor&) = delete;
    RCUAccessor& operator=(const RCUAccessor&) = delete;
    const T& operator*() const noexcept { return *ptr_; }
    const T* operator->() const noexcept { return ptr_.get(); }
    explicit operator bool() const noexcept { return ptr_ != nullptr; }
    void Reset() { ptr_.reset(); }
};

// ---------------------------------------------------------------------------
// RCUStore<T> - 无锁读、原子写
// ---------------------------------------------------------------------------
template <typename T>
class RCUStore {
    std::atomic<std::shared_ptr<const T>> current_;
public:
    explicit RCUStore(std::shared_ptr<const T> initial) : current_(static_cast<std::shared_ptr<const T>&&>(initial)) {}
    explicit RCUStore(T initial) : current_(std::make_shared<const T>(static_cast<T&&>(initial))) {}

    RCUAccessor<T> Read() const {
        return RCUAccessor<T>(current_.load(std::memory_order_acquire));
    }

    const T* PeekUnsafe() const {
        return current_.load(std::memory_order_acquire).get();
    }

    template <typename Fn>
    void Update(Fn&& update_fn) {
        auto current = current_.load(std::memory_order_acquire);
        auto copy = std::make_shared<T>(*current);
        update_fn(*copy);
        auto expected = current;
        while (!current_.compare_exchange_weak(expected, copy,
                std::memory_order_release, std::memory_order_acquire)) {
            current = expected;
            copy = std::make_shared<T>(*current);
            update_fn(*copy);
            expected = current;
        }
    }

    void Store(std::shared_ptr<const T> new_data) {
        current_.store(static_cast<std::shared_ptr<const T>&&>(new_data), std::memory_order_release);
    }
};

// ---------------------------------------------------------------------------
// RCUMap<K, V> - 无锁读 Map
// ---------------------------------------------------------------------------
template <typename K, typename V, typename Hash = std::hash<K>>
class RCUMap {
    using MapType = std::unordered_map<K, V, Hash>;
    RCUMap(const RCUMap&) = delete;
    RCUMap& operator=(const RCUMap&) = delete;
public:
    RCUMap() : store_(std::make_shared<const MapType>()) {}

    std::optional<V> Get(const K& key) const {
        auto snapshot = store_.Read();
        auto it = snapshot->find(key);
        if (it != snapshot->end()) return it->second;
        return std::nullopt;
    }

    bool Contains(const K& key) const {
        auto snapshot = store_.Read();
        return snapshot->find(key) != snapshot->end();
    }

    size_t Size() const {
        auto snapshot = store_.Read();
        return snapshot->size();
    }

    void Set(const K& key, const V& value) {
        store_.Update([&](MapType& m) { m[key] = value; });
    }

    bool Erase(const K& key) {
        bool found = false;
        store_.Update([&](MapType& m) {
            auto it = m.find(key);
            if (it != m.end()) { m.erase(it); found = true; }
        });
        return found;
    }

    MapType Snapshot() const {
        auto snapshot = store_.Read();
        return *snapshot;
    }

private:
    RCUStore<MapType> store_;
};

} // namespace hy2::perf
