#include "cryptoxx.hpp"

#include <memory>
#include <print>
#include <cstring>
#include <sys/mman.h>

namespace Cryptoxx {

// ============================================================
// FreeMmap implementation
// ============================================================

template <typename T>
void FreeMmap<T>::operator()(T* ptr) const {
    if (!ptr) return;

    auto p = reinterpret_cast<uint8_t*>(ptr);
    
    // Allow read/write to wipe
    (void)mprotect(p, bytes, PROT_READ | PROT_WRITE);
    explicit_bzero(p, bytes);
    (void)munlock(p, bytes);
    (void)munmap(p, bytes);
}

// ============================================================
// secure_vector helpers
// ============================================================

template <typename T>
std::size_t secure_vector<T>::round_page(std::size_t n) {
    const std::size_t page = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
    return (n + page - 1) & ~(page - 1);
}

template <typename T>
void secure_vector<T>::allocate(std::size_t capacity) {
    if (capacity == 0)
        throw std::runtime_error("secure_vector: zero capacity");

    const std::size_t bytes = round_page(capacity * sizeof(T));

    void* mem = mmap(nullptr,
                     bytes,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1,
                     0);

    if (mem == MAP_FAILED)
        throw std::runtime_error("mmap failed");

    if (mlock(mem, bytes) != 0) {
        munmap(mem, bytes);
        throw std::runtime_error("mlock failed");
    }

    (void)madvise(mem, bytes, MADV_DONTDUMP);
    explicit_bzero(mem, bytes);

    if (mprotect(mem, bytes, PROT_NONE) != 0) {
        munlock(mem, bytes);
        munmap(mem, bytes);
        throw std::runtime_error("mprotect failed");
    }

    _data = std::unique_ptr<T[], FreeMmap<T>>(
        static_cast<T*>(mem),
        FreeMmap<T>{bytes}
    );

    _capacity = capacity;
}

// ============================================================
// secure_vector guards
// ============================================================

template <typename T>
secure_vector<T>::read_guard::read_guard(const T* ptr, std::size_t size, std::size_t bytes)
    : _ptr(ptr), _size(size), _bytes(bytes) {
    if (mprotect(const_cast<T*>(_ptr), _bytes, PROT_READ) != 0)
        throw std::runtime_error("mprotect(PROT_READ) failed");
}

template <typename T>
secure_vector<T>::read_guard::~read_guard() {
    (void)mprotect(const_cast<T*>(_ptr), _bytes, PROT_NONE);
}

template <typename T>
const T* secure_vector<T>::read_guard::begin() const noexcept {
    return _ptr;
}

template <typename T>
const T* secure_vector<T>::read_guard::end() const noexcept {
    return _ptr + _size;
}

template <typename T>
std::size_t secure_vector<T>::read_guard::size() const noexcept {
    return _size;
}

template <typename T>
secure_vector<T>::write_guard::write_guard(T* ptr, std::size_t size, std::size_t bytes)
    : _ptr(ptr), _size(size), _bytes(bytes) {
    if (mprotect(_ptr, _bytes, PROT_READ | PROT_WRITE) != 0)
        throw std::runtime_error("mprotect(PROT_RW) failed");
}

template <typename T>
secure_vector<T>::write_guard::~write_guard() {
    (void)mprotect(_ptr, _bytes, PROT_NONE);
}

template <typename T>
T* secure_vector<T>::write_guard::data() noexcept {
    return _ptr;
}

template <typename T>
std::size_t secure_vector<T>::write_guard::size() const noexcept {
    return _size;
}

// ============================================================
// secure_vector public API
// ============================================================

template <typename T>
secure_vector<T>::secure_vector(std::size_t n)
    : _size(n), _capacity(0) {
    allocate(n);
}

template <typename T>
secure_vector<T>::secure_vector(std::span<const uint8_t> input)
    : _size(0), _capacity(0) {
    const std::size_t n = input.size();
    allocate(n);
    assign(input);
}

template <typename T>
void secure_vector<T>::assign(std::span<const uint8_t> input) {
    const std::size_t n = input.size();
    if (n > _capacity)
        throw std::runtime_error("secure_vector overflow");

    write_guard w(_data.get(), _capacity, _capacity * sizeof(T));
    for (std::size_t i = 0; i < n; ++i) {
        w.data()[i] = static_cast<uint8_t>(input[i]);
    }
    _size = n;
}

template <typename T>
typename secure_vector<T>::read_guard secure_vector<T>::scoped_read() const {
    return read_guard(_data.get(), _size, _capacity * sizeof(T));
}

template <typename T>
typename secure_vector<T>::write_guard secure_vector<T>::scoped_write() {
    return write_guard(_data.get(), _capacity, _capacity * sizeof(T));
}

template <typename T>
std::size_t secure_vector<T>::size() const noexcept {
    return _size;
}

template <typename T>
std::size_t secure_vector<T>::capacity() const noexcept {
    return _capacity;
}

template <typename T>
bool secure_vector<T>::empty() const noexcept {
    return _size == 0;
}

template <typename T>
secure_vector<T>::secure_vector(secure_vector&&) noexcept = default;

template <typename T>
secure_vector<T>&
secure_vector<T>::operator=(secure_vector&&) noexcept = default;

template <typename T>
secure_vector<T>::~secure_vector() = default;

// ============================================================
// Explicit instantiations
// ============================================================

template class secure_vector<uint8_t>;
template struct FreeMmap<uint8_t>;

} // namespace Cryptoxx
