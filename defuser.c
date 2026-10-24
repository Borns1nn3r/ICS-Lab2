#include "defuser.h"
#include <inttypes.h>
#include <stdio.h>

/* Unsigned arithmetic reproduces the 32-bit wraparound of eax. */
static int write_answer(char *out, size_t cap, const uint32_t *values, size_t count) {
    size_t used = 0;
    if (!out || !cap || !count) return 1;
    for (size_t i = 0; i < count; ++i) {
        int n = snprintf(out + used, cap - used, "%s%" PRIu32, i ? " " : "", values[i]);
        if (n < 0 || (size_t)n >= cap - used) return 1;
        used += (size_t)n;
    }
    return 0;
}

int solve_phase_1(uint64_t c, char *out, size_t cap) {
    uint32_t lo = (uint32_t)c, mid = (uint32_t)(c >> 16), hi = (uint32_t)(c >> 32);
    uint32_t s2 = hi ^ (lo + 0xa517u);
    uint32_t s0 = (lo + 4u * mid) ^ 0x22fbu;
    uint32_t value = 2u * s0 + (s2 ^ 0x90fdu);
    return write_answer(out, cap, &value, 1);
}

int solve_phase_2(uint64_t c, char *out, size_t cap) {
    uint32_t v[6];
    v[0] = (uint32_t)((c >> 39) & 127u) + 4u;
    for (unsigned i = 1; i < 6; ++i)
        v[i] = ((2u * v[i - 1]) ^ (uint32_t)((c >> (9u + i)) & 15u)) + 11u * i;
    return write_answer(out, cap, v, 6);
}

int solve_phase_3(uint64_t c, char *out, size_t cap) {
    /* Jump-table order differs from the named case-function order. */
    uint32_t v[2] = {(uint32_t)c & 7u, 0};
    uint32_t x = (uint32_t)(c >> 3) ^ (uint32_t)(c >> 32);
    switch (v[0]) {
        case 0: v[1] = 5u * x + 0x337bbu; break;
        case 1: v[1] = (2u * x) ^ 0x8674u; break;
        case 2: v[1] = (x ^ 0xfdafu) + (x >> 1); break;
        case 3: v[1] = 3u * x + 0xab5au; break;
        case 4: v[1] = 5u * x + 0x25143u; break;
        case 5: v[1] = (x ^ 0x7461u) + (x >> 1); break;
        case 6: v[1] = 5u * x + 0x5800u; break;
        case 7: v[1] = (2u * x) ^ 0xcc3au; break;
    }
    return write_answer(out, cap, v, 2);
}

static uint32_t walk(uint32_t target, uint32_t lo, uint32_t hi, uint32_t salt) {
    uint32_t mid = lo + ((hi - lo) >> 1);
    if (target == mid) return (mid + 1u) ^ salt;
    uint32_t child = target < mid ? walk(target, lo, mid - 1u, salt)
                                  : walk(target, mid + 1u, hi, salt);
    return (5u * child) ^ (mid + salt) ^ (target < mid ? 0x13u : 0x1cu);
}

int solve_phase_4(uint64_t c, char *out, size_t cap) {
    uint32_t salt = (uint32_t)(c >> 7) ^ (uint32_t)(c >> 32);
    uint32_t v = walk((uint32_t)c & 127u, 0, 127, salt);
    return write_answer(out, cap, &v, 1);
}

int solve_phase_5(uint64_t c, char *out, size_t cap) {
    /* Physical node order at p5_nodes, with addresses converted to indices. */
    static const unsigned heads[8] = {0, 5, 10, 3, 4, 7, 1, 8};
    static const unsigned next[12] = {5, 8, 2, 4, 7, 10, 2, 1, 11, 6, 3, 9};
    static const uint32_t ids[12] = {
        0x239u, 0xb4cu, 0x322u, 0x857u, 0xa62u, 0x62du,
        0x93cu, 0x417u, 0x787u, 0x5cu, 0x54au, 0x163u
    };
    static const uint32_t weights[12] = {
        0x7449u, 0xe124u, 0xc1adu, 0x8254u, 0xf770u, 0xd812u,
        0xc126u, 0xfffu, 0x4957u, 0x6caau, 0xf88au, 0xa71au
    };
    unsigned node = heads[c & 7u], hops = (unsigned)((c >> 3) & 3u);
    uint32_t acc = (uint32_t)(c >> 6) ^ (uint32_t)(c >> 32) ^ 0x8bd1u;
    for (unsigned i = 0; i <= hops; ++i) {
        acc = ((acc + weights[node]) * 5u) ^ ids[node];
        if (i != hops) node = next[node];
    }
    uint32_t v[2] = {acc, ids[node]};
    return write_answer(out, cap, v, 2);
}

static uint32_t operation(unsigned slot, uint32_t x) {
    switch (slot) {
        case 0: return (x ^ (x >> 2)) + 0x8e5u;
        case 1: case 5: return (x >> 2) | (x << 30);
        case 2: case 3: return ((x << 5) | (x >> 27)) ^ 0xfd46u;
        case 4: return (x ^ 0x9737u) + (x << 5);
        case 6: return (x + 0x6b91u) ^ (x >> 7);
        case 7: return (2u * x + 0x1b0fu) ^ (5u * x);
    }
    return 0;
}

int solve_phase_6(uint64_t c, char *out, size_t cap) {
    uint32_t x = (uint32_t)(c >> 6) ^ (uint32_t)(c >> 32);
    x = operation((unsigned)(c & 7u), x) ^ 0xdb95u;
    x = operation((unsigned)((c >> 3) & 7u), x) + 0xd1a2u;
    return write_answer(out, cap, &x, 1);
}

int solve_secret(uint64_t c, uint64_t context, char *out, size_t cap) {
    uint32_t a = (uint32_t)c ^ (uint32_t)(c >> 32);
    uint32_t b = (uint32_t)context ^ (uint32_t)(context >> 32);
    uint32_t selector = (uint32_t)context & 3u;
    uint32_t x = a ^ b;
    uint32_t mixed = ((x >> 5) ^ 0x3a90u) + (x ^ 0x28au);
    uint32_t second = mixed ^ (selector * 0x28au) ^ (uint32_t)(context >> 16);
    uint32_t third = second ^ (b + selector + 0x3a90u + (a >> 5));
    if (!out || !cap) return 1;
    /* Gate requires OPEN at byte 32; numeric suffix begins at byte 36. */
    int n = snprintf(out, cap, "%032uOPEN%" PRIu32 " %" PRIu32 " %" PRIu32,
                     0u, selector, second, third);
    return n < 0 || (size_t)n >= cap;
}
