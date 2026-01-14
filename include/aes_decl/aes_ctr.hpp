#pragma once
#ifndef CRYPTOXX_AES_CTR_HPP_
#define CRYPTOXX_AES_CTR_HPP_

#include <memory>
#include <span>
#include <cstring>

#include "cipher.hpp"
#include "secure_vector.hpp"

namespace Cryptoxx {
    
class AesCtr : public Cipher {
public:
    explicit AesCtr(std::size_t key_bits);
    void set_key(const secure_vector<uint8_t>& key) override;
    void set_iv(const secure_vector<uint8_t>& iv) override;
    
    secure_vector<uint8_t> encrypt(const secure_vector<uint8_t>& plain) override;
    secure_vector<uint8_t> decrypt(const secure_vector<uint8_t> crypt) override;
    
    std::size_t key_size() const noexcept override { return _key_bits/8; };
    std::size_t iv_size() const noexcept override { return 16; };
    
    ~AesCtr() override = default;
    
private:
    std::size_t _key_bits;
    secure_vector<uint8_t> _key;
    secure_vector<uint8_t> _iv;
};
    
}

#endif // CRYPTOXX_AES_CTR_HPP_