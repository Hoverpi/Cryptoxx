#pragma once
#ifndef CRYPTOXX_RANDOM_HPP_
#define CRYPTOXX_RANDOM_HPP_

#include "secure_vector.hpp" 

#include <print>
#include <sys/random.h>

namespace Cryptoxx {

// ============================================================
// Random
// ============================================================

class Random {
public:
    // ===================== constructor =====================
    explicit Random() noexcept = default;
    
    // ===================== randomness =====================
    template <typename T>
    secure_vector<T> randomness(std::size_t bytes) const {
        static_assert(std::is_same_v<T, uint8_t>, "secure_vector only supports uint8_t");
    
        if (bytes == 0)
            return {};
        
        secure_vector<T> tmp(bytes);
        
        auto w = tmp.scoped_write_capacity();
        
        ssize_t random_numbers = getrandom(w.data(), bytes, GRND_NONBLOCK);
        
        if (random_numbers < 0) {
            if (random_numbers == EAGAIN) {
                throw std::runtime_error("Low quality randomness. Not enough entropy (EAGAIN)");
            } else {
                throw std::runtime_error("getrandom failed");
            }
        }
        
        if (static_cast<std::size_t>(random_numbers) != bytes) {
            throw std::runtime_error("getrandom returned partial data");
        }
        
        tmp._size = bytes;         
        
        return tmp;
    }
    
    // ===================== rule of 5 =====================
    Random(const Random&) = delete;
    Random& operator=(const Random&) = delete;

    Random(Random&&) noexcept = default;
    Random& operator=(Random&&) noexcept = default;

    ~Random() = default;
};

}

#endif // CRYPTOXX_RANDOM_HPP_