#include "aes_decl/aes_ctr.hpp"

#include <print>

namespace Cryptoxx {
    
AesCtr::AesCtr(std::size_t key_bits)
    : _key_bits(key_bits),
      _key(key_bits / 8),
      _iv(16) {
    if (key_bits != 128 && key_bits != 192 && key_bits != 256)
        throw std::invalid_argument("AesCtr: unsupported key size");
}

void AesCtr::set_key(const secure_vector<uint8_t>& key) {
    if (key.size() != key_size()) 
        throw std::invalid_argument("AesCtr::set_key: wrong key size");
    
    _key.append(key);
}
void AesCtr::set_iv(const secure_vector<uint8_t>& iv) {
    if (iv.size() != iv_size()) 
        throw std::invalid_argument("AesCtr::iv_key: wrong iv size");
    
    _iv.append(iv);
}
secure_vector<uint8_t> AesCtr::encrypt(const secure_vector<uint8_t>& plain) {
    if (_key.size() < 1)
        throw std::runtime_error("AesCtr::encrypt: key not set");

    secure_vector<uint8_t> out(plain.size());
    out.append(plain);

    std::println("Encrypt");

    return out;
    
}
secure_vector<uint8_t> AesCtr::decrypt(const secure_vector<uint8_t> crypt) {
    secure_vector<uint8_t> secret(crypt.size());
    secret.append(crypt);
    
    std::println("Decrypt");
    
    return secret;
}
    
} // Cryptoxx