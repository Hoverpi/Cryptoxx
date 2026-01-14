#pragma once
#ifndef CRYPTOXX_CIPHER_HPP_
#define CRYPTOXX_CIPHER_HPP_

#include "secure_vector.hpp"
#include <span>

namespace Cryptoxx {
    
class Cipher {
public:
    virtual void set_key(const secure_vector<uint8_t>& key) = 0;
    virtual void set_iv(const secure_vector<uint8_t>& iv) = 0;
    
    virtual secure_vector<uint8_t> encrypt(const secure_vector<uint8_t>& plain) = 0;
    virtual secure_vector<uint8_t> decrypt(const secure_vector<uint8_t> crypt) = 0;
    
    virtual std::size_t key_size() const noexcept = 0;
    virtual std::size_t iv_size() const noexcept = 0;

    virtual ~Cipher() = default;
};
    
}

#endif // CRYPTOXX_CIPHER_HPP_