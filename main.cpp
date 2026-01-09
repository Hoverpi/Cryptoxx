#include "cryptoxx.hpp"
#include <string>
#include <print>
#include <ostream>

int main() {
    std::string text = "12345678901234567890";
    
    Cryptoxx::secure_vector<uint8_t> plain(text.begin(), text.end());
    
    auto r = plain.scoped_read();
    for (auto e: r) std::println("data: {}", static_cast<char>(e));
    
    // std::unique_ptr<Cipher> cipher1 = Cryptoxx::Aes::create("CTR(AES-256)");
    
    // Cryptoxx::RandomSeed rng;
    
    // const auto key = rng.random_vector<std::vector<uint8_t>>(32);
    // const auto iv = rng.random_vector<std::vector<uint8_t>>(16);
    
    // // set key/vector
    // cipher->set_key(key);
    // cipher->set_iv(iv);
    
    // std::vector<uint8_t> encrypted = cipher->encrypt(plain);
    
    // std::unique_ptr<Cipher> cipher2 = Cryptoxx::Aes::create("CTR(AES-256)");
    
    // // set key/vector
    // cipher2->set_key(key);
    // cipher2->set_iv(iv);
    
    // Cryptoxx::secure_vector<uint8_t> decrypted = cipher2->decrypt(encrypted);
    
    return 0;
}