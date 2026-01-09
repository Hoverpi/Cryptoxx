#pragma once
#ifndef CRYPTOXX_HPP_
#define CRYPTOXX_HPP_

#include <memory>
#include <print>
#include <cstring>
#include <sys/mman.h>

namespace Cryptoxx {
    
// class Cipher {
// public:
//     virtual void set_key(const std::vector& key);
//     virtual void set_iv(const std::vector& iv);
//     virtual std::vector<uint8_t> encrypt(const secure_vector<uint8_t> plain);
//     virtual secure_vector<uint8_t> decrypt(const std::vector<uint8_t> crypt);
// };

// ============================================================
// FreeMmap (deleter declaration)
// ============================================================

template <typename T>
struct FreeMmap {
    std::size_t bytes;
    void operator()(T* ptr) const;
};

// ============================================================
// secure_vector (class declaration)
// ============================================================

template <typename T>
class secure_vector {
    static_assert(std::is_same_v<T, uint8_t>, "secure_vector only supports uint8_t");

private:
    // read_guard: temporarily set pages to PROT_READ for the lifetime
    class read_guard {
    public:
        read_guard(const T* ptr, std::size_t size, std::size_t bytes);
        ~read_guard();

        const T* begin() const noexcept;
        const T* end()   const noexcept;
        std::size_t size() const noexcept;

        read_guard(const read_guard&) = delete;
        read_guard& operator=(const read_guard&) = delete;

    private:
        const T* _ptr;
        std::size_t _size;
        std::size_t _bytes;
    };

    // write_guard: temporarily set pages to PROT_READ|PROT_WRITE
    class write_guard {
    public:
        write_guard(T* ptr, std::size_t size, std::size_t bytes);
        ~write_guard();

        T* data() noexcept;
        std::size_t size() const noexcept;

        write_guard(const write_guard&) = delete;
        write_guard& operator=(const write_guard&) = delete;

    private:
        T* _ptr;
        std::size_t _size;
        std::size_t _bytes;
    };

private:
    std::size_t _size {0};
    std::size_t _capacity {0};
    std::unique_ptr<T[], FreeMmap<T>> _data;

private:
    static std::size_t round_page(std::size_t n);
    void allocate(std::size_t capacity);

public:
    // allocate capacity bytes (number of T elements)
    explicit secure_vector(std::size_t n);

    // construct from a span of bytes (non-templated)
    explicit secure_vector(std::span<const uint8_t> input);

    // assign from a span of bytes
    void assign(std::span<const uint8_t> input);

    // scoped accessors
    read_guard  scoped_read() const;
    write_guard scoped_write();

    // observers
    std::size_t size() const noexcept;
    std::size_t capacity() const noexcept;
    bool empty() const noexcept;

    // non-copyable (sensitive)
    secure_vector(const secure_vector&) = delete;
    secure_vector& operator=(const secure_vector&) = delete;

    // movable
    secure_vector(secure_vector&&) noexcept;
    secure_vector& operator=(secure_vector&&) noexcept;

    ~secure_vector();
};

// explicit instantiation declarations (implementation will instantiate)
extern template class secure_vector<uint8_t>;
extern template struct FreeMmap<uint8_t>;

} // namespace Cryptoxx

#endif // CRYPTOXX_HPP_
