#include "lynx_constants.hpp"
#include "lynx_matrices.hpp"
#include "lynx_owf.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

using namespace sig;

namespace {

template <std::size_t N, std::size_t W, std::size_t SW>
poly_secpar<secpar::s160> correct_matvec(
    const std::array<std::array<uint64_t, SW>, N>& matrix,
    const poly_secpar<secpar::s160>& input) {
    std::array<uint64_t, W> in_words{};
    input.store(in_words.data());
    uint8_t out[20]{};
    for (unsigned row = 0; row < N; ++row) {
        uint64_t dot = 0;
        for (unsigned word = 0; word < W; ++word) {
            dot ^= matrix[row][word] & in_words[word];
        }
        if (__builtin_parityll(dot)) {
            out[row / 8] ^= static_cast<uint8_t>(1u << (row % 8));
        }
    }
    return poly_secpar<secpar::s160>::load(out);
}

bool parse_hex(const char* text, uint8_t* out, std::size_t bytes) {
    if (std::strlen(text) != 2 * bytes) {
        return false;
    }
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < bytes; ++i) {
        const int hi = nibble(text[2 * i]);
        const int lo = nibble(text[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

void print_hex(const char* label, const uint8_t* bytes, std::size_t size) {
    std::printf("%s=", label);
    for (std::size_t i = 0; i < size; ++i) std::printf("%02X", bytes[i]);
    std::printf("\n");
}

}  // namespace

int main(int argc, char** argv) {
    const char* iv_hex =
        argc > 1 ? argv[1] : "8157886D49D8323C198C1942B963AE68F3E4ACEC";
    const char* key_hex =
        argc > 2 ? argv[2] : "B1C3CBC9F8F59B19CC899F8560F906F889EEA5FE";
    uint8_t iv[20]{};
    uint8_t key[20]{};
    if (!parse_hex(iv_hex, iv, sizeof(iv)) ||
        !parse_hex(key_hex, key, sizeof(key))) {
        std::fprintf(stderr, "usage: %s [iv-hex-20] [key-hex-20]\n", argv[0]);
        return 2;
    }

    lynx::lynx_matrices<secpar::s160> mats{};
    lynx::lynx_init<secpar::s160>(mats, iv, sizeof(iv));

    const auto k = poly_secpar<secpar::s160>::load(key);
    const auto c0 = poly_secpar<secpar::s160>::load(mats.C0.data());
    const auto c1 = poly_secpar<secpar::s160>::load(mats.C1.data());

    const auto l0k = correct_matvec<160, 3, 8>(mats.L0, k);
    const auto v1 = lynx::lynx_poly_s1<secpar::s160>(k + c0);
    const auto v2_spec = lynx::lynx_poly_s2<secpar::s160>(l0k + c1);
    const auto w1 = correct_matvec<160, 3, 8>(mats.L1, v1);
    const auto w2 = correct_matvec<160, 3, 8>(mats.L2, v2_spec);
    const auto w3 = correct_matvec<160, 3, 8>(mats.L3, k + v1 + v2_spec);
    const auto spec_y = lynx::lynx_poly_mul<secpar::s160>(w1, w2) + w3;

    uint8_t spec_y_bytes[20]{};
    uint8_t implementation_y[20]{};
    spec_y.store(spec_y_bytes);
    lynx::owf_lynx<secpar::s160>(implementation_y, key, iv, sizeof(iv));

    print_hex("iv", iv, sizeof(iv));
    print_hex("key", key, sizeof(key));
    print_hex("C0", mats.C0.data(), sizeof(mats.C0));
    print_hex("C1", mats.C1.data(), sizeof(mats.C1));
    print_hex("implementation_t", implementation_y, sizeof(implementation_y));
    print_hex("spec_t", spec_y_bytes, sizeof(spec_y_bytes));
    std::printf("difference=%s\n",
                std::memcmp(implementation_y, spec_y_bytes, 20) == 0 ? "none"
                                                                     : "different");
    return 0;
}
