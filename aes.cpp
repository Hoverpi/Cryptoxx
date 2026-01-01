#include "aes.hpp"

std::unique_ptr<Cipher> Aes::create(std::string_view str) {
    return std::unique_ptr<Cipher>();
}

void Aes::set_key(const std::vector<uint8_t> key) {
    
}

void Aes::set_iv(const std::vector<uint8_t> iv) {
    
}