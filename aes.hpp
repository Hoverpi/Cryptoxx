#pragma once
#ifndef AES_HPP_
#define AES_HPP_

#include <vector>
#include <string_view>
#include <cstdint>
#include <memory>
#include "cipher_modes.hpp"


class Aes final {
private:

public:
	static std::unique_ptr<Cipher> create(std::string_view str);
	void set_key(const std::vector<uint8_t> key);
	void set_iv(const std::vector<uint8_t> iv);	
	
};

#endif // #ifndef AES_HPP_