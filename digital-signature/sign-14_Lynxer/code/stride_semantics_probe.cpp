#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "lynx_constants.hpp"
#include "lynx_matrices.hpp"

using namespace sig;
using gf = poly_secpar<secpar::s160>;

static constexpr size_t N = 160;
using Storage = std::array<std::array<uint64_t, 8>, N>;

struct Vec {
    std::array<uint64_t, 3> w{};
    Vec operator+(const Vec& o) const {
        Vec r;
        for (size_t i = 0; i < 3; ++i) r.w[i] = w[i] ^ o.w[i];
        return r;
    }
    bool operator==(const Vec& o) const { return w == o.w; }
    unsigned bit(size_t i) const { return (w[i / 64] >> (i % 64)) & 1; }
    void set_bit(size_t i) { w[i / 64] ^= uint64_t(1) << (i % 64); }
};

static Vec from_gf(gf x) {
    Vec r;
    uint8_t b[20];
    x.store(b);
    std::memcpy(r.w.data(), b, 20);
    return r;
}

static gf to_gf(Vec x) {
    uint8_t b[20];
    std::memcpy(b, x.w.data(), 20);
    return gf::load(b);
}

template <size_t W>
static Vec apply_stored(const std::array<std::array<uint64_t, W>, N>& M, Vec x) {
    Vec r;
    for (size_t i = 0; i < N; ++i) {
        uint64_t d = (M[i][0] & x.w[0]) ^ (M[i][1] & x.w[1]) ^ (M[i][2] & x.w[2]);
        d ^= d >> 32; d ^= d >> 16; d ^= d >> 8;
        d ^= d >> 4; d ^= d >> 2; d ^= d >> 1;
        if (d & 1) r.set_bit(i);
    }
    return r;
}

static Vec apply_flat(const Storage& M, Vec x) {
    std::array<std::array<uint64_t, 3>, N> R{};
    const uint64_t* flat = M[0].data();
    for (size_t i = 0; i < N; ++i)
        for (size_t j = 0; j < 3; ++j) R[i][j] = flat[3 * i + j];
    return apply_stored(R, x);
}

static size_t rank(const Storage& M, bool flat) {
    std::array<std::array<uint64_t, 3>, N> rows{};
    if (flat) {
        const uint64_t* p = M[0].data();
        for (size_t i = 0; i < N; ++i)
            for (size_t j = 0; j < 3; ++j) rows[i][j] = p[3 * i + j];
    } else {
        for (size_t i = 0; i < N; ++i)
            for (size_t j = 0; j < 3; ++j) rows[i][j] = M[i][j];
    }
    size_t r = 0;
    for (size_t c = 0; c < N; ++c) {
        size_t p = r;
        while (p < N && !((rows[p][c / 64] >> (c % 64)) & 1)) ++p;
        if (p == N) continue;
        std::swap(rows[p], rows[r]);
        for (size_t i = 0; i < N; ++i) {
            if (i == r || !((rows[i][c / 64] >> (c % 64)) & 1)) continue;
            for (size_t j = 0; j < 3; ++j) rows[i][j] ^= rows[r][j];
        }
        ++r;
    }
    return r;
}

static void print20(const char* name, Vec x) {
    const auto* p = reinterpret_cast<const uint8_t*>(x.w.data());
    std::printf("%s=", name);
    for (size_t i = 0; i < 20; ++i) std::printf("%02x", p[i]);
    std::printf("\n");
}

int main() {
    const uint8_t seed[20] = {
        0x81,0x57,0x88,0x6d,0x49,0xd8,0x32,0x3c,0x19,0x8c,
        0x19,0x42,0xb9,0x63,0xae,0x68,0xf3,0xe4,0xac,0xec
    };
    uint8_t key_bytes[20] = {};
    key_bytes[0] = 1;
    lynx::lynx_matrices<secpar::s160> mats;
    lynx::lynx_init(mats, seed, sizeof(seed));

    Vec k;
    std::memcpy(k.w.data(), key_bytes, 20);
    Vec c0 = from_gf(gf::load(mats.C0.data()));
    Vec c1 = from_gf(gf::load(mats.C1.data()));
    Vec v1 = from_gf(lynx::lynx_poly_s1<secpar::s160>(to_gf(k + c0)));

    auto output = [&](bool flat) {
        auto L = [&](const Storage& M, Vec x) {
            return from_gf(lynx::lynx_L<secpar::s160>(
                reinterpret_cast<const uint64_t (*)[3]>(M.data()), to_gf(x)));
        };
        Vec L0k = flat ? apply_flat(mats.L0, k) : apply_stored(mats.L0, k);
        Vec v2 = from_gf(lynx::lynx_poly_s2<secpar::s160>(to_gf(L0k + (flat ? c0 : c1))));
        Vec L1v1 = flat ? apply_flat(mats.L1, v1) : apply_stored(mats.L1, v1);
        Vec L2v2 = flat ? apply_flat(mats.L2, v2) : apply_stored(mats.L2, v2);
        Vec L3s = flat ? apply_flat(mats.L3, k + v1 + v2) : apply_stored(mats.L3, k + v1 + v2);
        return from_gf(lynx::lynx_poly_mul<secpar::s160>(to_gf(L1v1), to_gf(L2v2))) + L3s;
    };

    std::printf("seed=");
    for (uint8_t b : seed) std::printf("%02x", b);
    std::printf("\nkey=");
    for (uint8_t b : key_bytes) std::printf("%02x", b);
    std::printf("\n");
    print20("spec_conforming_output", output(false));
    print20("implemented_flat_output", output(true));
    std::printf("ranks stored L0,L1,L2,L3: %zu,%zu,%zu,%zu\n",
                rank(mats.L0,false), rank(mats.L1,false), rank(mats.L2,false), rank(mats.L3,false));
    std::printf("ranks flat   L0,L1,L2,L3: %zu,%zu,%zu,%zu\n",
                rank(mats.L0,true), rank(mats.L1,true), rank(mats.L2,true), rank(mats.L3,true));
}
