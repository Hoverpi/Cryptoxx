#pragma once
#ifndef RANDOM_HPP_
#define RANDOM_HPP_

#include <concepts>

namespace Cryptoxx {

class RandomSeed {
public:
    template <typename T>
    concept resizable_byte_buffer = std::default_initializable<T> && requires(T t, size_t n) {
        { t.resize(n) };
        { t.data() } -> std::convertible_to<uint8_t*>;
        { t.size() } -> std::same_as<size_t>;
    }
    
    template <typename T>
    T random_vector(size_t bytes) {
        T type;
        type.resize(bytes);
        randomize(type.begin(), type.end());
        return type;
    }
};

}

#endif // #ifndef RANDOM_HPP_