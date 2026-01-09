#pragma once
#ifndef CRYPTOXX_HPP_
#define CRYPTOXX_HPP_

#define __STDC_WANT_LIB_EXT1__ 1

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

template <typename T>
struct FreeMmap {
    std::size_t bytes;
    void operator()(T* ptr) const {
        if (!ptr) return; 
        auto p = reinterpret_cast<uint8_t*>(ptr);
        
        (void)mprotect(p, bytes, PROT_READ | PROT_WRITE);
        explicit_bzero(p, bytes);
        (void)munlock(p, bytes);
        (void)munmap(p, bytes);
        
        std::println("Clean memory: vector pointer begin: {} - end: {} with size {}", static_cast<void*>(p), static_cast<void*>(p + bytes), bytes);
    }
};

template <typename T>
class secure_vector {
    
static_assert(std::is_same<T, uint8_t>::value, "T need to bee uint8_t");

    class read_guard {
    private:
        const T* ptr_;
        std::size_t size_;
        std::size_t bytes_;
    
    public:
        read_guard(const T* p, std::size_t s, std::size_t b) : ptr_(p), size_(s), bytes_(b) {
            if (mprotect(const_cast<T*>(ptr_), bytes_, PROT_READ) != 0) {
                throw std::runtime_error("mprotect(PROT_READ) failed in read_guard");
            }
        }
        
        ~read_guard() {
            (void)mprotect(const_cast<T*>(ptr_), bytes_, PROT_NONE);
        }
        
        const T* begin() const noexcept { return ptr_; }
        const T* end() const noexcept { return ptr_ + size_; }
        std::size_t size() const noexcept { return size_; }
        
        read_guard(const read_guard&) = delete;
        read_guard& operator=(const read_guard&) = delete;
    };
    
    class write_guard {
    private:
        T* ptr_;
        std::size_t size_;
        std::size_t bytes_;
    
    public:
        write_guard(T* p, std::size_t s, std::size_t b) : ptr_(p), size_(s), bytes_(b) {
            if (mprotect(ptr_, bytes_, PROT_READ | PROT_WRITE) != 0) {
                throw std::runtime_error("mprotect(PROT_READ|PROT_WRITE) failed in write_guard");
            }
        }

        ~write_guard() {
            (void)mprotect(ptr_, bytes_, PROT_NONE);
        }
        
        T* data() noexcept { return ptr_; }
        std::size_t size() const noexcept { return size_; }

        write_guard(const write_guard&) = delete;
        write_guard& operator=(const write_guard&) = delete;
    };

private:
    std::size_t _size {0};
    std::size_t _capacity {0};
    std::unique_ptr<T[], FreeMmap<T>> _data;
    
    static std::size_t round_page(std::size_t n) {
        const std::size_t page = sysconf(_SC_PAGESIZE);
        return (n + page - 1) & ~(page - 1);
    }
    
    // helper memory managment functions
    void allocate(std::size_t cap) {
        if (cap == 0)
            throw std::runtime_error("secure_vector: zero capacity not supported");
        
        const std::size_t bytes = round_page(cap * sizeof(T));
        
        T* mem = static_cast<T*>(mmap(nullptr,
            bytes,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, 
            -1, 
            0
        ));
        
        if (mem == MAP_FAILED) 
            throw std::runtime_error("mmap failed");
        
        if (mlock(mem, bytes) != 0) {
            munmap(mem, bytes);
            throw std::runtime_error("mlock failed");
        }
        
        (void)madvise(mem, bytes, MADV_DONTDUMP);
        explicit_bzero(mem, bytes);
        
        mprotect(mem, bytes, PROT_NONE);
        
        _data = std::unique_ptr<T[], FreeMmap<T>>(mem, FreeMmap<T>{bytes});
        
        _capacity = cap;
    }

public:
    explicit secure_vector(size_t n) : _size(n), _capacity(n) {
        allocate(n);
    
        std::println(
            "Reserved memory: begin: {} - end: {} with size {}",
            static_cast<void*>(_data.get()),
            static_cast<void*>(_data.get() + _size),
            _size
        );
    }
    
    template <typename Iter> 
    explicit secure_vector(Iter begin, Iter end) : _size(0) {
        const size_t n = std::distance(begin, end);
        allocate(n);
        assign(begin, end);
        
        std::println(
            "Reserved memory: begin: {} - end: {} with size {}",
            static_cast<void*>(_data.get()),
            static_cast<void*>(_data.get() + _size),
            _size
        );
    }
    
    template <typename Iter>
    void assign(Iter begin, Iter end) {
        const size_t n = std::distance(begin, end);
        if (n > _capacity) throw std::runtime_error("secure_vector overflow");
        
        write_guard w(_data.get(), _capacity, _capacity * sizeof(T));
        std::size_t i = 0;
        for (auto it = begin; it != end; ++it, ++i)
            w.data()[i] = static_cast<uint8_t>(*it);

        _size = n;
    }
    
    // Access control functions (scoped_read / scoped_write)
    read_guard scoped_read() const {
        return read_guard(
            _data.get(),
            _size,
            _capacity * sizeof(T)
        );
    }
    write_guard scoped_write() {
        return write_guard(
            _data.get(),
            _capacity,
            _capacity * sizeof(T)
        );
    }
    
    // Observers (size / capacity / empty)
    size_t size() const noexcept { return _size; }
    size_t capacity() const noexcept { return _capacity; }
    bool empty() const noexcept { return _size == 0; }

  
    secure_vector(const secure_vector&) = delete;
    secure_vector& operator=(const secure_vector&) = delete;
    
    secure_vector(secure_vector&&) noexcept = default;
    secure_vector& operator=(secure_vector&&) noexcept = default;        
    
    ~secure_vector() = default; // unique_ptr handle it
};

} // namespace Cryptoxx

#endif // #include CRYPTOXX_HPP_