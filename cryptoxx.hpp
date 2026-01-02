#pragma once
#ifndef CRYPTOXX_HPP_
#define CRYPTOXX_HPP_

#include <vector>
#include <iterator>
#include <cstdlib>
#include <concepts>
#include <memory>
#include <cstdint>
#include <cstring>
#include <print>
#include <iostream>

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
    std::size_t size;
    void operator()(T* ptr) const {
        auto p = reinterpret_cast<uint8_t*>(ptr);
        if (ptr) {
            std::memset(p, 0, size);
            std::free(p);
        }
    std::println("Clean memory: vector pointer begin:{} - end:{} with size {}", static_cast<void*>(p), static_cast<void*>(p + size), size);
    }
};

// template <typename T>
//     concept resizable_byte_buffer = std::default_initializable<T> && requires(T t, size_t n) {
//         { t.resize(n) };
//         { t.data() } -> std::convertible_to<uint8_t*>;
//         { t.size() } -> std::same_as<size_t>;
//     };



template <typename T>
class secure_vector {
    
static_assert(std::is_same<T, uint8_t>::value, "T need to bee uint8_t");

private:
    std::size_t _size;
    std::size_t _capacity;
    std::unique_ptr<T[], FreeMmap<T>> _data;

public:
    secure_vector(size_t n) : _size(n), _capacity(n), _data(std::unique_ptr<T[], FreeMmap<T>>(static_cast<T*>(std::aligned_alloc(64, n * sizeof(T))), FreeMmap<T>(n * sizeof(T)))) {
        std::println("Reserved memory: begin: {} - end: {} with size {}", static_cast<void*>(_data.get()), static_cast<void*>(_data.get() + _size), _size);
    }
    
    template <typename Iter> 
    secure_vector(Iter begin, Iter end): secure_vector(std::distance(begin, end)) {
        std::copy(begin, end, _data.get());
        std::println("distance: {}", std::distance(begin, end));
    }
    
    size_t size() const noexcept { 
        return _size; 
    }
    
    size_t capacity() const noexcept {
        return _capacity;
    }
    
    bool empty() const noexcept {
        return _size == 0;
    }
    
    void reserve(std::size_t new_cap) noexcept {
        if (new_cap <= _capacity) {
            return;
        }
        
        std::size_t growth_cap = _capacity == 0 ? 1 : _capacity;
        while (growth_cap < new_cap) growth_cap <<= 1;
        
        constexpr std::size_t alignment = 64;
        std::size_t bytes = growth_cap * sizeof(T);
        bytes = (bytes + alignment - 1) & ~(alignment - 1);
        
        std::println("old_cap: {} new_cap: {}", _capacity, growth_cap);
                
        T* new_alloc = static_cast<T*>(std::aligned_alloc(64, growth_cap * sizeof(T)));
        if (!new_alloc) return;
        
        std::memcpy(new_alloc, _data.get(), _size * sizeof(T));
        
        _data.reset(new_alloc);
    
        _capacity = growth_cap;
    }
    
    void shrink_to_fit() noexcept {
        
    }
    
    
    
    T* data() {
        return _data.get(); 
    }

    T* begin() { 
        return data(); 
    }
    T* end() { 
        return data() + _size; 
    }
    
    secure_vector(const secure_vector&) = delete;
    secure_vector& operator=(const secure_vector&) = delete;
    
    secure_vector(secure_vector&&) noexcept = default;
    secure_vector& operator=(secure_vector&&) noexcept = default;        
    
    ~secure_vector() = default; // unique_ptr handle it
};

}

#endif // #include CRYPTOXX_HPP_