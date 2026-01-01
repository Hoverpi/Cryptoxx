#pragma once
#ifndef CRYPTOXX_HPP_
#define CRYPTOXX_HPP_

#include <vector>
#include <iterator>
#include <cstdlib>
#include <concepts>
#include <memory>
#include <cstdint>

#include <print>

namespace Cryptoxx {

// class Cipher {
// public:
//     virtual void set_key(const std::vector& key);
//     virtual void set_iv(const std::vector& iv);
//     virtual std::vector<uint8_t> encrypt(const secure_vector<uint8_t> plain);
//     virtual secure_vector<uint8_t> decrypt(const std::vector<uint8_t> crypt);
// };

struct FreeMmap {
    size_t size;
    void operator()(uint8_t* ptr) const {
        if (ptr) {
            std::fill(ptr, ptr + size, 0);
            free(ptr);
        }
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

// static_assert(resizable_byte_buffer<T>, "T must satisfy the resizable_byte_buffer concept");

private:
    size_t _size;
    std::unique_ptr<T[], FreeMmap> _data;

public:
    secure_vector(size_t n) : _size(n), _data(static_cast<T*>(std::aligned_alloc(64, n * sizeof(T))), FreeMmap{n}) {
        if (!_data) throw std::bad_alloc();
    }

    template <typename Iter>
    secure_vector(Iter begin, Iter end) : secure_vector(std::distance(begin, end)) {
        std::copy(begin, end, _data.get());
        std::println("{}", std::distance(begin, end));
    }
    
    size_t size() const { 
        return _size; 
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

    ~secure_vector() = default; // unique_ptr handle it
};

}

#endif // #include CRYPTOXX_HPP_