#pragma once
#ifndef CRYPTOXX_AES_HPP_
#define CRYPTOXX_AES_HPP_

#include <span>
#include <string_view>
#include <memory>
#include <string>

#include "cipher.hpp"
#include "aes_ctr.hpp"

namespace Cryptoxx {

class Aes final {
public:
    static inline std::unique_ptr<Cryptoxx::Cipher> create(std::string_view s) {
        if (!verify_descriptor(s))
            throw std::invalid_argument("Aes::create failed: incorrect format");

        auto l = s.find('(');
        auto m = s.find('-');
        auto r = s.find(')');

        auto mode = std::string(s.substr(0, l));
        auto algo = std::string(s.substr(l + 1, m - l - 1));
        auto bits_str = std::string(s.substr(m + 1, r - m - 1));
        const std::size_t bits = static_cast<std::size_t>(std::stoul(bits_str));

        if (mode != "CTR" || algo != "AES")
            throw std::invalid_argument("Aes::create: unsupported mode/algo");

        if (bits != 128 && bits != 192 && bits != 256)
            throw std::invalid_argument("Aes::create: unsupported key size");

        return std::make_unique<AesCtr>(bits);
    }
private:
    static inline bool verify_descriptor(std::string_view s) {
        const auto l = s.find('(');
        const auto m = s.find('-');
        const auto r = s.find(')');

        if (l == std::string_view::npos ||
            m == std::string_view::npos ||
            r == std::string_view::npos) return false;
        if (!(l < m && m < r)) return false;
        if (r != s.size() - 1) return false;

        const auto mode = s.substr(0, l);
        const auto algo = s.substr(l + 1, m - l - 1);
        const auto bits = s.substr(m + 1, r - m - 1);

        if (mode.empty() || algo.empty() || bits.empty()) return false;

        auto is_upper = [](char c) {
            return static_cast<bool>(std::isupper(static_cast<unsigned char>(c)));
        };
        auto is_digit = [](char c) {
            return static_cast<bool>(std::isdigit(static_cast<unsigned char>(c)));
        };

        return std::all_of(mode.begin(), mode.end(), is_upper)
            && std::all_of(algo.begin(), algo.end(), is_upper)
            && std::all_of(bits.begin(), bits.end(), is_digit);
    }
};

} // namespace Cryptoxx

#endif // CRYPTOXX_AES_HPP_
