#pragma once
#ifndef CRYPTOXX_HPP_
#define CRYPTOXX_HPP_

#include <vector>
#include <memory>
#include <span>
#include <cstring>
#include <sys/mman.h>

namespace Cryptoxx {

// ============================================================
// FreeMmap
// ============================================================

template <typename T>
struct FreeMmap {
    std::size_t bytes;
    void operator()(T* ptr) const;
};

// ============================================================
// secure_vector
// ============================================================

template <typename T>
class secure_vector {
    static_assert(std::is_same_v<T, uint8_t>, "secure_vector only supports uint8_t");

private:
    class read_guard {
    public:
        const T* begin() const noexcept;
        const T* end()   const noexcept;
        std::size_t size() const noexcept;
        ~read_guard();

        read_guard(const read_guard&) = delete;
        read_guard& operator=(const read_guard&) = delete;

    private:
        friend class secure_vector;
        read_guard(const T* ptr, std::size_t size, std::size_t bytes);

        const T* _ptr;
        std::size_t _size;
        std::size_t _bytes;
    };

    class write_guard {
    public:
        T* data() noexcept;
        std::size_t size() const noexcept;
        ~write_guard();

        write_guard(const write_guard&) = delete;
        write_guard& operator=(const write_guard&) = delete;

    private:
        friend class secure_vector;
        write_guard(T* ptr, std::size_t size, std::size_t bytes);

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
    void allocate_page(std::size_t capacity);
    void allocate(std::size_t capacity);

public:
    // ---- constructors ----
    secure_vector() noexcept = default;
    explicit secure_vector(std::size_t capacity);
    explicit secure_vector(std::span<const uint8_t> input);

    // ---- template adapters ----
    template <typename Iter>
    secure_vector(Iter first, Iter last);

    template <typename Range>
    explicit secure_vector(const Range& r);

    // ---- assignment ----
    void append(std::span<const uint8_t> input);

    // convenience overloads:
    void append(const std::vector<uint8_t>& v) { 
        append(std::span<const uint8_t>(v)); 
    }
    void append(std::string_view sv) {
        append(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(sv.data()), sv.size()));
    }
    void append(const void* data, std::size_t size) {
        append(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(data), size));
    }
    void append(std::initializer_list<uint8_t> il) {
        append(std::span<const uint8_t>(il.begin(), il.size()));
    }

    template <typename Iter>
    void append(Iter first, Iter last) {
        // best-effort for contiguous iterators — we forward to span-based append
        append(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(std::to_address(first)),
            static_cast<std::size_t>(std::distance(first, last))
        ));
    }

    template <typename Range>
    requires std::ranges::contiguous_range<Range> &&
             std::convertible_to<std::ranges::range_value_t<Range>, uint8_t>
    void append(const Range& r) {
        append(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(std::data(r)),
            static_cast<std::size_t>(std::size(r))
        ));
    }
    
    // ---- scoped access ----
    read_guard  scoped_read() const;
    write_guard scoped_write();           // overwrite existing elements
    write_guard scoped_write_capacity();  // write into full capacity

    // ---- observers ----
    std::size_t size() const noexcept;
    std::size_t capacity() const noexcept;
    bool empty() const noexcept;

    // ---- rule of 5 ----
    secure_vector(const secure_vector&) = delete;
    secure_vector& operator=(const secure_vector&) = delete;
    secure_vector(secure_vector&&) noexcept;
    secure_vector& operator=(secure_vector&&) noexcept;
    ~secure_vector();
};

// ============================================================
// TEMPLATE IMPLEMENTATIONS (header-only)
// ============================================================

template <typename T>
template <typename Iter>
secure_vector<T>::secure_vector(Iter first, Iter last)
    : secure_vector(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(std::to_address(first)),
        static_cast<std::size_t>(std::distance(first, last))
      )) {}

template <typename T>
template <typename Range>
secure_vector<T>::secure_vector(const Range& r)
    : secure_vector(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(std::data(r)),
        std::size(r)
      )) {}
      
// explicit instantiations
extern template class secure_vector<uint8_t>;
extern template struct FreeMmap<uint8_t>;

} // namespace Cryptoxx

#endif // CRYPTOXX_HPP_
