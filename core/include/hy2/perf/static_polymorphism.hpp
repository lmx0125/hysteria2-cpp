// static_polymorphism.hpp - CRTP 静态多态 (MSVC 兼容)
#pragma once

#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace hy2::perf {

template <typename Derived>
class ByteReaderCRTP {
public:
    size_t Read(uint8_t* p, size_t n) {
        return static_cast<Derived*>(this)->ReadImpl(p, n);
    }
};

template <typename Derived>
class ByteWriterCRTP {
public:
    void Write(const uint8_t* p, size_t n) {
        static_cast<Derived*>(this)->WriteImpl(p, n);
    }
    size_t WriteSome(const uint8_t* p, size_t n) {
        return static_cast<Derived*>(this)->WriteSomeImpl(p, n);
    }
};

class MemoryReader : public ByteReaderCRTP<MemoryReader> {
    const uint8_t* data_;
    size_t len_;
    size_t pos_;
public:
    MemoryReader(const uint8_t* d, size_t l)
        : data_(d), len_(l), pos_(0) {}

    size_t ReadImpl(uint8_t* p, size_t n) {
        size_t avail = len_ - pos_;
        size_t take = (n < avail) ? n : avail;
        if (take > 0) {
            std::memcpy(p, data_ + pos_, take);
            pos_ += take;
        }
        return take;
    }

    void Reset() { pos_ = 0; }
};

class MemoryWriter : public ByteWriterCRTP<MemoryWriter> {
    uint8_t* buf_;
    size_t cap_;
    size_t pos_;
public:
    MemoryWriter(uint8_t* b, size_t c)
        : buf_(b), cap_(c), pos_(0) {}

    void WriteImpl(const uint8_t* p, size_t n) {
        if (pos_ + n > cap_) n = cap_ - pos_;
        std::memcpy(buf_ + pos_, p, n);
        pos_ += n;
    }

    size_t WriteSomeImpl(const uint8_t* p, size_t n) {
        size_t avail = cap_ - pos_;
        size_t take = (n < avail) ? n : avail;
        std::memcpy(buf_ + pos_, p, take);
        pos_ += take;
        return take;
    }

    size_t Written() const { return pos_; }
    void Reset() { pos_ = 0; }
};

class SmallBufferWriter {
    static constexpr size_t kSmallBufSize = 128;

    struct VTable {
        void (*write)(void*, const uint8_t*, size_t);
        void (*destroy)(void*);
    };

    template <typename T>
    static void WriteTrampoline(void* self, const uint8_t* p, size_t n) {
        static_cast<T*>(self)->WriteImpl(p, n);
    }

    template <typename T>
    static void DestroyTrampoline(void* self) {
        static_cast<T*>(self)->~T();
    }

    alignas(16) uint8_t storage_[kSmallBufSize];
    VTable* vtable_;
    void* ptr_;

public:
    template <typename T>
    explicit SmallBufferWriter(T impl) {
        if (sizeof(T) <= kSmallBufSize && alignof(T) <= 16) {
            new (storage_) T(static_cast<T&&>(impl));
            ptr_ = storage_;
        } else {
            ptr_ = new T(static_cast<T&&>(impl));
        }
        vtable_ = new VTable{WriteTrampoline<T>, DestroyTrampoline<T>};
    }

    void Write(const uint8_t* p, size_t n) {
        vtable_->write(ptr_, p, n);
    }

    ~SmallBufferWriter() {
        vtable_->destroy(ptr_);
    }

    SmallBufferWriter(const SmallBufferWriter&) = delete;
    SmallBufferWriter& operator=(const SmallBufferWriter&) = delete;
};

} // namespace hy2::perf
