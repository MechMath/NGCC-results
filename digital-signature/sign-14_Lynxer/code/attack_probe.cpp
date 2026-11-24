#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "lynx_matrices.hpp"
#include "lynx_owf.hpp"
#include "lynx_constants.hpp"

using namespace sig;
using gf = poly_secpar<secpar::s160>;
static constexpr size_t N = 160;

struct Vec {
    std::array<uint64_t, 3> w{};

    bool operator==(const Vec& o) const { return w == o.w; }
    Vec operator+(const Vec& o) const {
        Vec r;
        for (size_t i = 0; i < 3; ++i) r.w[i] = w[i] ^ o.w[i];
        return r;
    }
    bool zero() const { return !(w[0] | w[1] | w[2]); }
    unsigned bit(size_t i) const { return (w[i / 64] >> (i % 64)) & 1; }
    void set_bit(size_t i) { w[i / 64] ^= uint64_t(1) << (i % 64); }
};

static Vec from_gf(gf x) {
    Vec r;
    uint8_t b[20];
    x.store(b);
    std::memcpy(r.w.data(), b, sizeof(b));
    return r;
}

static gf to_gf(Vec x) {
    uint8_t b[20];
    std::memcpy(b, x.w.data(), sizeof(b));
    return gf::load(b);
}

static Vec apply_matrix(const uint64_t (*M)[3], Vec x) {
    Vec r;
    for (size_t i = 0; i < N; ++i) {
        uint64_t d = (M[i][0] & x.w[0]) ^ (M[i][1] & x.w[1]) ^ (M[i][2] & x.w[2]);
        d ^= d >> 32; d ^= d >> 16; d ^= d >> 8;
        d ^= d >> 4; d ^= d >> 2; d ^= d >> 1;
        if (d & 1) r.set_bit(i);
    }
    return r;
}

static bool solve(const std::array<Vec, N>& cols, Vec rhs, Vec& out) {
    struct Row {
        std::array<uint64_t, 3> c{};
        unsigned rhs = 0;
    };
    std::array<Row, N> a{};
    for (size_t i = 0; i < N; ++i) {
        for (size_t j = 0; j < N; ++j)
            if (cols[j].bit(i)) a[i].c[j / 64] ^= uint64_t(1) << (j % 64);
        a[i].rhs = rhs.bit(i);
    }
    size_t row = 0;
    std::array<size_t, N> pivot{};
    for (size_t col = 0; col < N; ++col) {
        size_t p = row;
        while (p < N && !((a[p].c[col / 64] >> (col % 64)) & 1)) ++p;
        if (p == N) continue;
        std::swap(a[p], a[row]);
        for (size_t i = 0; i < N; ++i)
            if (i != row && ((a[i].c[col / 64] >> (col % 64)) & 1)) {
                for (size_t k = 0; k < 3; ++k) a[i].c[k] ^= a[row].c[k];
                a[i].rhs ^= a[row].rhs;
            }
        pivot[row++] = col;
    }
    std::fprintf(stderr, "rank=%zu\n", row);
    for (size_t i = row; i < N; ++i)
        if (a[i].rhs && !(a[i].c[0] | a[i].c[1] | a[i].c[2])) return false;
    if (row != N) return false;
    out = Vec{};
    for (size_t i = 0; i < N; ++i)
        if (a[i].rhs) out.set_bit(pivot[i]);
    return true;
}

static Vec hex20(const char* h) {
    Vec r;
    for (size_t i = 0; i < 40; i += 2) {
        auto nib = [](char c) -> unsigned {
            return c <= '9' ? unsigned(c - '0') : unsigned((c | 32) - 'a' + 10);
        };
        unsigned char b = (nib(h[i]) << 4) | nib(h[i + 1]);
        reinterpret_cast<unsigned char*>(r.w.data())[i / 2] = b;
    }
    return r;
}

int main() {
    const char* seed_hex = "8157886D49D8323C198C1942B963AE68F3E4ACEC";
    const char* y_hex = "D4C54218A91840ACE548B6948EEB3D3DDE825177";
    Vec seed = hex20(seed_hex), y = hex20(y_hex);
    lynx::lynx_matrices<secpar::s160> mats;
    lynx::lynx_init(mats, reinterpret_cast<const uint8_t*>(seed.w.data()), 20);
    Vec c0 = from_gf(gf::load(mats.C0.data()));

    std::array<Vec, N> cols;
    for (int which = 0; which < 4; ++which) {
        const auto* Mw = reinterpret_cast<const uint64_t (*)[3]>(
            which == 0 ? mats.L0.data() : which == 1 ? mats.L1.data()
            : which == 2 ? mats.L2.data() : mats.L3.data());
        for (size_t i = 0; i < N; ++i) {
            Vec e; e.set_bit(i);
            cols[i] = apply_matrix(Mw, e);
        }
        std::fprintf(stderr, "L%d: ", which);
        Vec dummy;
        (void)solve(cols, Vec{}, dummy);
    }
    for (size_t i = 0; i < N; ++i) {
        Vec e; e.set_bit(i);
        cols[i] = apply_matrix(reinterpret_cast<const uint64_t (*)[3]>(mats.L0.data()), e);
    }
    Vec k;
    if (!solve(cols, c0, k)) { std::puts("L0 singular"); return 2; }
    Vec s1in = k + c0;
    if (s1in.zero()) { std::puts("s1 zero"); return 3; }
    gf v1g = lynx::lynx_poly_s1<secpar::s160>(to_gf(s1in));
    Vec v1 = from_gf(v1g);
    gf A = lynx::lynx_L<secpar::s160>(
        reinterpret_cast<const uint64_t (*)[3]>(mats.L1.data()), v1g);
    const auto* L2 = reinterpret_cast<const uint64_t (*)[3]>(mats.L2.data());
    const auto* L3 = reinterpret_cast<const uint64_t (*)[3]>(mats.L3.data());
    for (size_t i = 0; i < N; ++i) {
        Vec e; e.set_bit(i);
        Vec L2e = apply_matrix(L2, e);
        // Field multiplication is linear in its left argument.
        Vec coeff = apply_matrix(L3, e) +
                    from_gf(lynx::lynx_poly_mul<secpar::s160>(A, to_gf(L2e)));
        cols[i] = coeff;
    }
    Vec rhs = y + apply_matrix(L3, k + v1);
    Vec v2;
    if (!solve(cols, rhs, v2)) { std::puts("F singular"); return 4; }

    std::printf("k=%016llx%016llx%016llx\n",
                (unsigned long long)k.w[2], (unsigned long long)k.w[1],
                (unsigned long long)k.w[0]);
    std::printf("v1=%016llx%016llx%016llx\n",
                (unsigned long long)v1.w[2], (unsigned long long)v1.w[1],
                (unsigned long long)v1.w[0]);
    std::printf("v2=%016llx%016llx%016llx\n",
                (unsigned long long)v2.w[2], (unsigned long long)v2.w[1],
                (unsigned long long)v2.w[0]);
    std::printf("L0k_plus_c0_zero=%d v2_check=%d\n",
                apply_matrix(reinterpret_cast<const uint64_t (*)[3]>(mats.L0.data()), k) == c0,
                apply_matrix(L2, v2).zero());
    return 0;
}
