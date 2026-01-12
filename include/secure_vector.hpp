#pragma once
#ifndef SECURE_VECTOR_HPP_
#define SECURE_VECTOR_HPP_

#include <vector>
#include <memory>
#include <span>
#include <cstring>
#include <sys/mman.h>

namespace Cryptoxx {

class Random;

// ============================================================
// FreeMmap
// ============================================================

template <typename T>
struct FreeMmap {
    std::size_t bytes;

    void operator()(T* ptr) const {
        if (!ptr) return;

        void* p = static_cast<void*>(ptr);
        (void)mprotect(p, bytes, PROT_READ | PROT_WRITE);
        explicit_bzero(p, bytes);
        (void)munlock(p, bytes);
        (void)munmap(p, bytes);
    }
};

// ============================================================
// secure_vector
// ============================================================

template <typename T>
class secure_vector {
    static_assert(std::is_same_v<T, uint8_t>,
                  "secure_vector only supports uint8_t");

private:
    // ===================== read_guard =====================
    class read_guard {
    public:
        const T* begin() const noexcept { return _ptr; }
        const T* end()   const noexcept { return _ptr + _size; }
        std::size_t size() const noexcept { return _size; }

        ~read_guard() {
            (void)mprotect(const_cast<T*>(_ptr), _bytes, PROT_NONE);
        }

        read_guard(const read_guard&) = delete;
        read_guard& operator=(const read_guard&) = delete;

    private:
        friend class secure_vector;

        read_guard(const T* ptr, std::size_t size, std::size_t bytes)
            : _ptr(ptr), _size(size), _bytes(bytes) {
            if (mprotect(const_cast<T*>(_ptr), _bytes, PROT_READ) != 0)
                throw std::runtime_error("mprotect(PROT_READ) failed");
        }

        const T* _ptr;
        std::size_t _size;
        std::size_t _bytes;
    };

    // ===================== write_guard =====================
    class write_guard {
    public:
        T* data() noexcept { return _ptr; }
        std::size_t size() const noexcept { return _size; }

        ~write_guard() {
            (void)mprotect(_ptr, _bytes, PROT_NONE);
        }

        write_guard(const write_guard&) = delete;
        write_guard& operator=(const write_guard&) = delete;

    private:
        friend class secure_vector;

        write_guard(T* ptr, std::size_t size, std::size_t bytes)
            : _ptr(ptr), _size(size), _bytes(bytes) {
            if (mprotect(_ptr, _bytes, PROT_READ | PROT_WRITE) != 0)
                throw std::runtime_error("mprotect(PROT_RW) failed");
        }

        T* _ptr;
        std::size_t _size;
        std::size_t _bytes;
    };

private:
    std::size_t _size {0};
    std::size_t _capacity {0};
    std::unique_ptr<T[], FreeMmap<T>> _data;

    friend class Random;

private:
    static std::size_t round_page(std::size_t n) {
        const std::size_t page =
            static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
        return (n + page - 1) & ~(page - 1);
    }

    void allocate_page(std::size_t capacity) {
        if (capacity == 0)
            throw std::runtime_error("secure_vector: zero capacity");

        const std::size_t bytes = round_page(capacity * sizeof(T));

        void* mem = mmap(nullptr, bytes,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS,
                         -1, 0);

        if (mem == MAP_FAILED)
            throw std::runtime_error("mmap failed");

        if (mlock(mem, bytes) != 0) {
            munmap(mem, bytes);
            throw std::runtime_error("mlock failed");
        }

        explicit_bzero(mem, bytes);
        (void)mprotect(mem, bytes, PROT_NONE);

        _data = std::unique_ptr<T[], FreeMmap<T>>(
            static_cast<T*>(mem),
            FreeMmap<T>{bytes}
        );

        _capacity = capacity;
    }

    void allocate(std::size_t capacity) {
        if (capacity <= _capacity)
            return;

        std::size_t new_capacity = _capacity ? (_capacity << 1) : 1;
        if (new_capacity < capacity)
            new_capacity = capacity;

        secure_vector tmp;
        tmp.allocate_page(new_capacity);

        if (_size > 0) {
            auto src = scoped_read();
            auto dst = tmp.scoped_write_capacity();
            std::memcpy(dst.data(), src.begin(), _size);
            tmp._size = _size;
        }

        *this = std::move(tmp);
    }

public:
    // ===================== constructors =====================
    secure_vector() noexcept = default;

    explicit secure_vector(std::size_t capacity) {
        allocate(capacity);
    }

    explicit secure_vector(std::span<const uint8_t> input) {
        allocate(input.size());
        append(input);
    }

    template <typename Iter>
    secure_vector(Iter first, Iter last)
        : secure_vector(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(std::to_address(first)),
            static_cast<std::size_t>(std::distance(first, last))
        )) {}

    template <typename Range>
    explicit secure_vector(const Range& r)
        requires std::ranges::contiguous_range<Range>
        : secure_vector(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(std::data(r)),
            std::size(r)
        )) {}

    // ===================== append =====================
    void append(std::span<const uint8_t> input) {
        if (input.empty())
            return;

        allocate(_size + input.size());

        auto w = scoped_write_capacity();
        std::memcpy(w.data() + _size, input.data(), input.size());
        _size += input.size();
    }

    void append(const std::vector<uint8_t>& v) {
        append(std::span<const uint8_t>(v));
    }

    void append(std::string_view sv) {
        append(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(sv.data()), sv.size()));
    }

    void append(const void* data, std::size_t size) {
        append(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(data), size));
    }

    void append(std::initializer_list<uint8_t> il) {
        append(std::span<const uint8_t>(il.begin(), il.size()));
    }

    // ===================== scoped access =====================
    read_guard scoped_read() const {
        return read_guard(_data.get(), _size, _capacity);
    }

    write_guard scoped_write() {
        return write_guard(_data.get(), _size, _capacity);
    }

    write_guard scoped_write_capacity() {
        return write_guard(_data.get(), _capacity, _capacity);
    }

    // ===================== observers =====================
    std::size_t size() const noexcept { return _size; }
    std::size_t capacity() const noexcept { return _capacity; }
    bool empty() const noexcept { return _size == 0; }

    // ===================== rule of 5 =====================
    secure_vector(const secure_vector&) = delete;
    secure_vector& operator=(const secure_vector&) = delete;

    secure_vector(secure_vector&&) noexcept = default;
    secure_vector& operator=(secure_vector&&) noexcept = default;

    ~secure_vector() = default;
};

} // namespace Cryptoxx

#endif // SECURE_VECTOR_HPP_
