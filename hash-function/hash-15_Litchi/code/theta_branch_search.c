#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct { uint64_t w[5]; } V;

static V rows[320], invcols[320];

static V vxor(V a, V b) {
    for (int i = 0; i < 5; i++) a.w[i] ^= b.w[i];
    return a;
}

static int wt(V a) {
    int n = 0;
    for (int i = 0; i < 5; i++) n += __builtin_popcountll(a.w[i]);
    return n;
}

static void setbit(V *a, int i, int bit) {
    a[i].w[bit >> 6] |= UINT64_C(1) << (bit & 63);
}

static void vsetbit(V *a, int lane, int bit) {
    a->w[lane] |= UINT64_C(1) << bit;
}

/* Build M or M^T. */
static void build(int transpose, const int *t) {
    for (int out = 0; out < 5; out++) {
        for (int in = 0; in < 5; in++) {
            int ro = transpose ? in : out;
            int ci = transpose ? out : in;
            for (int k = 0; k < 64; k++) {
                V *row = &rows[64 * ci + k];
                if (ro == ci) vsetbit(row, ro, k);
                int b1 = transpose ? (k + t[ro]) & 63 : (k - t[ro]) & 63;
                vsetbit(row, ro, b1);
                int b2 = transpose ? (k - t[ci]) & 63 : (k + t[ci]) & 63;
                vsetbit(row, ro, b2);
            }
        }
    }
}

/* Put the 320x640 matrix [M | I] in reduced row echelon form.
   Then invcols[k] is M^{-1} e_k. */
static void invert(void) {
    const int N = 320;
    uint64_t a[N][10], b[10];
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < 10; j++) a[i][j] = 0;
        for (int j = 0; j < 5; j++) a[i][j] = rows[i].w[j];
        a[i][5 + (i >> 6)] |= UINT64_C(1) << (i & 63);
    }
    for (int col = 0; col < N; col++) {
        int p = col;
        while (p < N && !((a[p][col >> 6] >> (col & 63)) & 1)) p++;
        if (p == N) { fprintf(stderr, "singular at %d\n", col); exit(2); }
        if (p != col) {
            for (int j = 0; j < 10; j++) { b[j] = a[p][j]; a[p][j] = a[col][j]; a[col][j] = b[j]; }
        }
        for (int r = 0; r < N; r++) {
            if (r != col && ((a[r][col >> 6] >> (col & 63)) & 1))
                for (int j = 0; j < 10; j++) a[r][j] ^= a[col][j];
        }
    }
    for (int k = 0; k < N; k++) {
        V r = {{0, 0, 0, 0, 0}};
        for (int i = 0; i < N; i++)
            if ((a[i][5 + (k >> 6)] >> (k & 63)) & 1) vsetbit(&r, i >> 6, i & 63);
        invcols[k] = r;
    }
}

static int best;
static V bestin, bestout;
static int side;

static void search(V *cols, int start, int need, V acc, V picked) {
    if (need == 0) {
        int w = wt(acc);
        if (w + side < best) { best = w + side; bestout = acc; bestin = picked; }
        return;
    }
    int last = 320 - need;
    for (int k = start; k <= last; k++) {
        V pp = picked;
        vsetbit(&pp, k >> 6, k & 63);
        search(cols, k + 1, need - 1, vxor(acc, cols[k]), pp);
    }
}

static int run_one(int transpose, const int *t) {
    build(transpose, t);
    invert();
    best = 1000;
    V zero = {{0, 0, 0, 0, 0}};
    for (side = 1; side <= 5; side++) {
        search(rows, 0, side, zero, zero);
        search(invcols, 0, side, zero, zero);
    }
    printf("transpose=%d min=%d\n", transpose, best);
    for (int i = 0; i < 5; i++) printf("in[%d]=%016llx out[%d]=%016llx\n", i,
        (unsigned long long)bestin.w[i], i, (unsigned long long)bestout.w[i]);
    return best;
}

int main(void) {
    const int t[5] = {31, 1, 4, 21, 22};
    return run_one(0, t) != 12 || run_one(1, t) != 12;
}
