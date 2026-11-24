#include "lynx_matrices.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

using namespace sig;

namespace {

struct Row160 {
    uint64_t w[3];
};

template <std::size_t N, std::size_t W>
Row160 get_row(const std::array<std::array<uint64_t, W>, N>& matrix,
               std::size_t index) {
    Row160 row{};
    for (std::size_t j = 0; j < 3; ++j) {
        row.w[j] = matrix[index][j];
    }
    return row;
}

void xor_row(Row160& dst, const Row160& src) {
    for (std::size_t j = 0; j < 3; ++j) {
        dst.w[j] ^= src.w[j];
    }
}

int bit(const Row160& row, unsigned col) {
    return static_cast<int>((row.w[col / 64] >> (col % 64)) & 1);
}

template <std::size_t N, std::size_t W>
unsigned rank(const std::array<std::array<uint64_t, W>, N>& matrix) {
    std::array<Row160, N> basis{};
    for (std::size_t i = 0; i < N; ++i) {
        basis[i] = get_row(matrix, i);
    }
    unsigned pivot_count = 0;
    for (unsigned col = 0; col < N; ++col) {
        unsigned pivot = pivot_count;
        while (pivot < N && bit(basis[pivot], col) == 0) {
            ++pivot;
        }
        if (pivot == N) {
            continue;
        }
        std::swap(basis[pivot_count], basis[pivot]);
        for (unsigned row = 0; row < N; ++row) {
            if (row != pivot_count && bit(basis[row], col)) {
                xor_row(basis[row], basis[pivot_count]);
            }
        }
        ++pivot_count;
    }
    return pivot_count;
}

unsigned augmented_rank_160(const std::array<std::array<uint64_t, 8>, 160>& matrix,
                            const uint8_t* target) {
    constexpr unsigned n = 160;
    std::array<std::array<uint64_t, 6>, n> rows{};
    for (std::size_t i = 0; i < n; ++i) {
        for (std::size_t j = 0; j < 3; ++j) {
            rows[i][j] = matrix[i][j];
        }
        if (target != nullptr) {
            for (unsigned byte = 0; byte < 20; ++byte) {
                rows[i][3 + byte / 8] |=
                    static_cast<uint64_t>(target[byte]) << (8 * (byte % 8));
            }
        }
    }
    unsigned rank_out = 0;
    for (unsigned col = 0; col < n; ++col) {
        unsigned pivot = rank_out;
        while (pivot < n && ((rows[pivot][col / 64] >> (col % 64)) & 1) == 0) {
            ++pivot;
        }
        if (pivot == n) {
            continue;
        }
        std::swap(rows[rank_out], rows[pivot]);
        for (unsigned row = 0; row < n; ++row) {
            if (row != rank_out &&
                ((rows[row][col / 64] >> (col % 64)) & 1) != 0) {
                for (unsigned word = 0; word < 6; ++word) {
                    rows[row][word] ^= rows[rank_out][word];
                }
            }
        }
        ++rank_out;
    }
    for (unsigned row = rank_out; row < n; ++row) {
        bool left_zero = true;
        for (unsigned word = 0; word < 3; ++word) {
            left_zero &= rows[row][word] == 0;
        }
        if (left_zero &&
            (rows[row][3] | rows[row][4] | rows[row][5]) != 0) {
            return n + 1;
        }
    }
    return rank_out;
}

bool in_image_160(const std::array<std::array<uint64_t, 8>, 160>& matrix,
                  const uint8_t target[20]) {
    return augmented_rank_160(matrix, nullptr) ==
           augmented_rank_160(matrix, target);
}

bool solve_effective_160(const std::array<std::array<uint64_t, 8>, 160>& matrix,
                         const uint8_t target[20], Row160& solution) {
    constexpr unsigned n = 160;
    const auto* flat = reinterpret_cast<const uint64_t*>(matrix.data());
    std::array<std::array<uint64_t, 6>, n> rows{};
    for (unsigned i = 0; i < n; ++i) {
        for (unsigned j = 0; j < 3; ++j) {
            rows[i][j] = flat[3 * i + j];
        }
        for (unsigned byte = 0; byte < 20; ++byte) {
            rows[i][3 + byte / 8] |=
                static_cast<uint64_t>(target[byte]) << (8 * (byte % 8));
        }
    }
    unsigned rank_out = 0;
    for (unsigned col = 0; col < n; ++col) {
        unsigned pivot = rank_out;
        while (pivot < n && ((rows[pivot][col / 64] >> (col % 64)) & 1) == 0) {
            ++pivot;
        }
        if (pivot == n) {
            continue;
        }
        std::swap(rows[rank_out], rows[pivot]);
        for (unsigned row = 0; row < n; ++row) {
            if (row != rank_out &&
                ((rows[row][col / 64] >> (col % 64)) & 1) != 0) {
                for (unsigned word = 0; word < 6; ++word) {
                    rows[row][word] ^= rows[rank_out][word];
                }
            }
        }
        ++rank_out;
    }
    solution = {};
    for (unsigned row = 0; row < rank_out; ++row) {
        unsigned pivot = 0;
        while (pivot < n &&
               ((rows[row][pivot / 64] >> (pivot % 64)) & 1) == 0) {
            ++pivot;
        }
        if (pivot < n &&
            ((rows[row][3 + pivot / 64] >> (pivot % 64)) & 1) != 0) {
            solution.w[pivot / 64] |= UINT64_C(1) << (pivot % 64);
        }
    }
    for (unsigned row = rank_out; row < n; ++row) {
        bool left_zero = true;
        for (unsigned word = 0; word < 3; ++word) {
            left_zero &= rows[row][word] == 0;
        }
        if (left_zero &&
            (rows[row][3] | rows[row][4] | rows[row][5]) != 0) {
            return false;
        }
    }
    return true;
}

unsigned effective_rank_160(const std::array<std::array<uint64_t, 8>, 160>& matrix,
                            const uint8_t* target) {
    constexpr unsigned n = 160;
    const auto* flat = reinterpret_cast<const uint64_t*>(matrix.data());
    std::array<std::array<uint64_t, 6>, n> rows{};
    for (unsigned i = 0; i < n; ++i) {
        for (unsigned j = 0; j < 3; ++j) {
            rows[i][j] = flat[3 * i + j];
        }
        if (target != nullptr) {
            for (unsigned byte = 0; byte < 20; ++byte) {
                rows[i][3 + byte / 8] |=
                    static_cast<uint64_t>(target[byte]) << (8 * (byte % 8));
            }
        }
    }
    unsigned rank_out = 0;
    for (unsigned col = 0; col < n; ++col) {
        unsigned pivot = rank_out;
        while (pivot < n && ((rows[pivot][col / 64] >> (col % 64)) & 1) == 0) {
            ++pivot;
        }
        if (pivot == n) {
            continue;
        }
        std::swap(rows[rank_out], rows[pivot]);
        for (unsigned row = 0; row < n; ++row) {
            if (row != rank_out &&
                ((rows[row][col / 64] >> (col % 64)) & 1) != 0) {
                for (unsigned word = 0; word < 6; ++word) {
                    rows[row][word] ^= rows[rank_out][word];
                }
            }
        }
        ++rank_out;
    }
    for (unsigned row = rank_out; row < n; ++row) {
        bool left_zero = true;
        for (unsigned word = 0; word < 3; ++word) {
            left_zero &= rows[row][word] == 0;
        }
        if (left_zero &&
            (rows[row][3] | rows[row][4] | rows[row][5]) != 0) {
            return n + 1;
        }
    }
    return rank_out;
}

bool parse_hex20(const char* text, uint8_t out[20]) {
    if (std::strlen(text) != 40) {
        return false;
    }
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    };
    for (unsigned i = 0; i < 20; ++i) {
        int hi = nibble(text[2 * i]);
        int lo = nibble(text[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    const char* seed_hex =
        argc > 1 ? argv[1] : "8157886D49D8323C198C1942B963AE68F3E4ACEC";
    uint8_t seed[20];
    uint8_t c0[20];
    if (!parse_hex20(seed_hex, seed)) {
        std::fprintf(stderr, "usage: %s [40-hex-seed]\n", argv[0]);
        return 2;
    }
    lynx::lynx_matrices<secpar::s160> mats{};
    lynx::lynx_init<secpar::s160>(mats, seed, sizeof(seed));
    if (argc > 2) {
        if (!parse_hex20(argv[2], c0)) {
            std::fprintf(stderr, "invalid c0 hex\n");
            return 2;
        }
    } else {
        std::memcpy(c0, mats.C0.data(), sizeof(c0));
    }
    std::printf("stored-row L0 rank=%u\n", rank(mats.L0));
    std::printf("effective-row L0 rank=%u\n", effective_rank_160(mats.L0, nullptr));
    std::printf("effective-row L1 rank=%u\n", effective_rank_160(mats.L1, nullptr));
    std::printf("effective-row L2 rank=%u\n", effective_rank_160(mats.L2, nullptr));
    std::printf("effective-row L3 rank=%u\n", effective_rank_160(mats.L3, nullptr));
    std::printf("C0=");
    for (uint8_t byte : c0) {
        std::printf("%02X", byte);
    }
    std::printf("\n");
    const auto* flat_l0 = reinterpret_cast<const uint64_t*>(mats.L0.data());
    std::printf("effective L0 row0=%016llx%016llx%016llx\n",
                static_cast<unsigned long long>(flat_l0[0]),
                static_cast<unsigned long long>(flat_l0[1]),
                static_cast<unsigned long long>(flat_l0[2]));
    std::printf("c0 in effective image(L0): %s\n",
                effective_rank_160(mats.L0, nullptr) ==
                        effective_rank_160(mats.L0, c0)
                    ? "yes"
                    : "no");
    Row160 solution{};
    if (solve_effective_160(mats.L0, c0, solution)) {
        uint8_t k_bytes[20]{};
        std::memcpy(k_bytes, solution.w, sizeof(k_bytes));
        const auto k = poly_secpar<secpar::s160>::load(k_bytes);
        const auto image = lynx::lynx_L<secpar::s160>(
            reinterpret_cast<const uint64_t(*)[3]>(mats.L0.data()), k);
        uint8_t image_bytes[20]{};
        image.store(image_bytes);
        std::printf("solved preimage verifies: %s\n",
                    std::memcmp(image_bytes, c0, sizeof(c0)) == 0 ? "yes" : "no");
        std::printf("image=");
        for (uint8_t byte : image_bytes) {
            std::printf("%02X", byte);
        }
        std::printf("\ntarget=");
        for (uint8_t byte : c0) {
            std::printf("%02X", byte);
        }
        std::printf("\n");
    } else {
        std::printf("solved preimage verifies: no solution\n");
    }
    return 0;
}
