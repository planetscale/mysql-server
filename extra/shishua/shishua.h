#ifndef shishua_h
#define shishua_h

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>

#define SHISHUA_TARGET_SCALAR 0
#define SHISHUA_TARGET_AVX2 1
#define SHISHUA_TARGET_SSE2 2
#define SHISHUA_TARGET_NEON 3

#ifndef SHISHUA_TARGET
#if defined(__AVX2__) && (defined(__x86_64__) || defined(_M_X64))
#define SHISHUA_TARGET SHISHUA_TARGET_AVX2
#elif defined(__x86_64__) || defined(_M_X64) || defined(__SSE2__) || \
    (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#define SHISHUA_TARGET SHISHUA_TARGET_SSE2
// GCC's NEON codegen leaves much to be desired, at least as of 9.2.0. The
// scalar path ends up being faster.
// Device: Google Pixel 2 XL, 2.46GHz Qualcomm Snapdragon 835
//   algorithm           |   GCC 9.2.0    |  Clang 9.0.1
//   shishua neon        | 0.2845 ns/byte | 0.0966 ns/byte
//   shishua scalar      | 0.2056 ns/byte | 0.2958 ns/byte
//   shishua half neon   | 0.5169 ns/byte | 0.1929 ns/byte
//   shishua half scalar | 0.2496 ns/byte | 0.2911 ns/byte
// Therefore, we only autoselect the NEON path on Clang, at least until GCC's
// NEON codegen improves.
#elif (defined(__ARM_NEON) || defined(__ARM_NEON__)) && defined(__clang__)
#define SHISHUA_TARGET SHISHUA_TARGET_NEON
#else
#define SHISHUA_TARGET SHISHUA_TARGET_SCALAR
#endif
#endif

// Nothing up my sleeve: those are the hex digits of Φ,
// the least approximable irrational number.
// $ echo 'scale=310;obase=16;(sqrt(5)-1)/2' | bc
static uint64_t phi[16] = {
    0x9E3779B97F4A7C15, 0xF39CC0605CEDC834, 0x1082276BF3A27251,
    0xF86C6A11D0C18E95, 0x2767F0B153D27B7F, 0x0347045B5BF1827F,
    0x01886F0928403002, 0xC1D64BA40F335E36, 0xF06AD7AE9717877E,
    0x85839D6EFFBD7DC6, 0x64D325D1C5371682, 0xCADD0CCCFDFFBBE1,
    0x626E33B8D04B4331, 0xBBF73C790D94F79D, 0x471C4AB3ED3D82A5,
    0xFEC507705E4AE6E5,
};

#if SHISHUA_TARGET == SHISHUA_TARGET_AVX2

#include <immintrin.h>

namespace shishua {
namespace detail {

class prng_state {
  __m256i state[4];
  __m256i output[4];
  __m256i counter;

 public:
  // buf's size must be a multiple of 128 bytes.
  void block(uint8_t *buf, size_t size) {
    __m256i o0 = output[0], o1 = output[1], o2 = output[2], o3 = output[3],
            s0 = state[0], s1 = state[1], s2 = state[2], s3 = state[3], t0, t1,
            t2, t3, u0, u1, u2, u3, cnt = counter;
    // The following shuffles move weak (low-diffusion) 32-bit parts of 64-bit
    // additions to strong positions for enrichment. The low 32-bit part of a
    // 64-bit chunk never moves to the same 64-bit chunk as its high part.
    // They do not remain in the same chunk. Each part eventually reaches all
    // positions ringwise: A to B, B to C, …, H to A.
    // You may notice that they are simply 256-bit rotations (96 and 160).
    __m256i shu0 = _mm256_set_epi32(4, 3, 2, 1, 0, 7, 6, 5),
            shu1 = _mm256_set_epi32(2, 1, 0, 7, 6, 5, 4, 3);
    // The counter is not necessary to beat PractRand.
    // It sets a lower bound of 2^71 bytes = 2 ZiB to the period,
    // or about 7 millenia at 10 GiB/s.
    // The increments are picked as odd numbers,
    // since only coprimes of the base cover the full cycle,
    // and all odd numbers are coprime of 2.
    // I use different odd numbers for each 64-bit chunk
    // for a tiny amount of variation stirring.
    // I used the smallest odd numbers to avoid having a magic number.
    __m256i increment = _mm256_set_epi64x(1, 3, 5, 7);

    // TODO: consider adding proper uneven write handling
    assert((size % 128 == 0) && "buf's size must be a multiple of 128 bytes.");

    for (size_t i = 0; i < size; i += 128) {
      _mm256_storeu_si256((__m256i *)&buf[i + 0], o0);
      _mm256_storeu_si256((__m256i *)&buf[i + 32], o1);
      _mm256_storeu_si256((__m256i *)&buf[i + 64], o2);
      _mm256_storeu_si256((__m256i *)&buf[i + 96], o3);

      // I apply the counter to s1,
      // since it is the one whose shift loses most entropy.
      s1 = _mm256_add_epi64(s1, cnt);
      s3 = _mm256_add_epi64(s3, cnt);
      cnt = _mm256_add_epi64(cnt, increment);

      // SIMD does not support rotations. Shift is the next best thing to
      // entangle bits with other 64-bit positions. We must shift by an odd
      // number so that each bit reaches all 64-bit positions, not just half. We
      // must lose bits of information, so we minimize it: 1 and 3. We use
      // different shift values to increase divergence between the two sides. We
      // use rightward shift because the rightmost bits have the least diffusion
      // in addition (the low bit is just a XOR of the low bits).
      u0 = _mm256_srli_epi64(s0, 1);
      u1 = _mm256_srli_epi64(s1, 3);
      u2 = _mm256_srli_epi64(s2, 1);
      u3 = _mm256_srli_epi64(s3, 3);
      t0 = _mm256_permutevar8x32_epi32(s0, shu0);
      t1 = _mm256_permutevar8x32_epi32(s1, shu1);
      t2 = _mm256_permutevar8x32_epi32(s2, shu0);
      t3 = _mm256_permutevar8x32_epi32(s3, shu1);
      // Addition is the main source of diffusion.
      // Storing the output in the state keeps that diffusion permanently.
      s0 = _mm256_add_epi64(t0, u0);
      s1 = _mm256_add_epi64(t1, u1);
      s2 = _mm256_add_epi64(t2, u2);
      s3 = _mm256_add_epi64(t3, u3);

      // Two orthogonally grown pieces evolving independently, XORed.
      o0 = _mm256_xor_si256(u0, t1);
      o1 = _mm256_xor_si256(u2, t3);
      o2 = _mm256_xor_si256(s0, s3);
      o3 = _mm256_xor_si256(s2, s1);
    }
    output[0] = o0;
    output[1] = o1;
    output[2] = o2;
    output[3] = o3;
    state[0] = s0;
    state[1] = s1;
    state[2] = s2;
    state[3] = s3;
    counter = cnt;
  }

  prng_state(::std::array<uint64_t, 4> seed) {
    constexpr int STEPS = 1;
    constexpr int ROUNDS = 13;

    uint8_t buf[128 * STEPS];
    // Diffuse first two seed elements in s0, then the last two. Same for s1.
    // We must keep half of the state unchanged so users cannot set a bad state.
    state[0] =
        _mm256_set_epi64x(phi[3], phi[2] ^ seed[1], phi[1], phi[0] ^ seed[0]);
    state[1] =
        _mm256_set_epi64x(phi[7], phi[6] ^ seed[3], phi[5], phi[4] ^ seed[2]);
    state[2] =
        _mm256_set_epi64x(phi[11], phi[10] ^ seed[3], phi[9], phi[8] ^ seed[2]);
    state[3] = _mm256_set_epi64x(phi[15], phi[14] ^ seed[1], phi[13],
                                 phi[12] ^ seed[0]);
    for (size_t i = 0; i < ROUNDS; i++) {
      block(buf, 128 * STEPS);
      state[0] = output[3];
      state[1] = output[2];
      state[2] = output[1];
      state[3] = output[0];
    }
  }
};

}  // namespace detail
}  // namespace shishua

#elif SHISHUA_TARGET == SHISHUA_TARGET_SSE2

// Note: cl.exe doesn't define __SSSE3__
#if defined(__SSSE3__) || defined(__AVX__)
#include <tmmintrin.h>  // SSSE3
#define SHISHUA_ALIGNR_EPI8(hi, lo, amt) _mm_alignr_epi8(hi, lo, amt)
#else
#include <emmintrin.h>  // SSE2
// Emulate _mm_alignr_epi8 for SSE2. It's a little slow.
// The compiler may convert it to a sequence of shufps instructions, which is
// perfectly fine.
#define SHISHUA_ALIGNR_EPI8(hi, lo, amt) \
  _mm_or_si128(_mm_slli_si128(hi, 16 - (amt)), _mm_srli_si128(lo, amt))
#endif

// Wrappers for x86 targets which usually lack these intrinsics.
// Don't call these with side effects.
#if defined(__x86_64__) || defined(_M_X64)
#define SHISHUA_SET_EPI64X(b, a) _mm_set_epi64x(b, a)
#define SHISHUA_CVTSI64_SI128(x) _mm_cvtsi64_si128(x)
#else
#define SHISHUA_SET_EPI64X(b, a)                        \
  _mm_set_epi32((int)(((uint64_t)(b)) >> 32), (int)(b), \
                (int)(((uint64_t)(a)) >> 32), (int)(a))
#define SHISHUA_CVTSI64_SI128(x) SHISHUA_SET_EPI64X(0, x)
#endif

namespace shishua {
namespace detail {

class prng_state {
  __m128i state[8];
  __m128i output[8];
  __m128i counter[2];

 public:
  void block(uint8_t *buf, size_t size) {
    __m128i counter_lo = counter[0], counter_hi = counter[1];
    // The counter is not necessary to beat PractRand.
    // It sets a lower bound of 2^71 bytes = 2 ZiB to the period,
    // or about 7 millenia at 10 GiB/s.
    // The increments are picked as odd numbers,
    // since only coprimes of the base cover the full cycle,
    // and all odd numbers are coprime of 2.
    // I use different odd numbers for each 64-bit chunk
    // for a tiny amount of variation stirring.
    // I used the smallest odd numbers to avoid having a magic number.

    // increment = { 7, 5, 3, 1 };
    __m128i increment_lo = SHISHUA_SET_EPI64X(5, 7);
    __m128i increment_hi = SHISHUA_SET_EPI64X(1, 3);

    // TODO: consider adding proper uneven write handling
    assert((size % 128 == 0) && "buf's size must be a multiple of 128 bytes.");

    for (size_t i = 0; i < size; i += 128) {
      // Write the current output block to state if it is not NULL
      if (buf != NULL) {
        for (size_t j = 0; j < 8; j++) {
          _mm_storeu_si128((__m128i *)&buf[i + (16 * j)], output[j]);
        }
      }

      // There are only 16 SSE registers (8 on i686), and we have to account for
      // temporary copies due to being stuck with 2-operand instructions.
      // Therefore, we use fixed iteration loops to reduce code complexity while
      // still allowing the compiler to easily unroll the loop.
      // We also try to keep variables active for as short as possible.
      for (size_t j = 0; j < 2; j++) {
        __m128i s_lo, s_hi, u0_lo, u0_hi, u1_lo, u1_hi, t_lo, t_hi;

        // Lane 0
        s_lo = state[4 * j + 0];
        s_hi = state[4 * j + 1];

        // SIMD does not support rotations. Shift is the next best thing to
        // entangle bits with other 64-bit positions. We must shift by an odd
        // number so that each bit reaches all 64-bit positions, not just half.
        // We must lose bits of information, so we minimize it: 1 and 3. We use
        // different shift values to increase divergence between the two sides.
        // We use rightward shift because the rightmost bits have the least
        // diffusion in addition (the low bit is just a XOR of the low bits).
        u0_lo = _mm_srli_epi64(s_lo, 1);
        u0_hi = _mm_srli_epi64(s_hi, 1);

        // The following shuffles move weak (low-diffusion) 32-bit parts of
        // 64-bit additions to strong positions for enrichment. The low 32-bit
        // part of a 64-bit chunk never moves to the same 64-bit chunk as its
        // high part. They do not remain in the same chunk. Each part eventually
        // reaches all positions ringwise: A to B, B to C, …, H to A. You may
        // notice that they are simply 256-bit rotations (96 and 160). Note:
        // This:
        //   x = (y << 96) | (y >> 160)
        // can be rewritten as this
        //   x_lo = (y_lo << 96) | (y_hi >> 32)
        //   x_hi = (y_hi << 96) | (y_lo >> 32)
        // which we can do with 2 _mm_alignr_epi8 instructions.
        t_lo = SHISHUA_ALIGNR_EPI8(s_lo, s_hi, 4);
        t_hi = SHISHUA_ALIGNR_EPI8(s_hi, s_lo, 4);

        // Addition is the main source of diffusion.
        // Storing the output in the state keeps that diffusion permanently.
        state[4 * j + 0] = _mm_add_epi64(t_lo, u0_lo);
        state[4 * j + 1] = _mm_add_epi64(t_hi, u0_hi);

        // Lane 1
        s_lo = state[4 * j + 2];
        s_hi = state[4 * j + 3];

        // I apply the counter to s1,
        // since it is the one whose shift loses most entropy.
        s_lo = _mm_add_epi64(s_lo, counter_lo);
        s_hi = _mm_add_epi64(s_hi, counter_hi);

        // Same as above but with different shifts
        u1_lo = _mm_srli_epi64(s_lo, 3);
        u1_hi = _mm_srli_epi64(s_hi, 3);

        t_lo = SHISHUA_ALIGNR_EPI8(s_hi, s_lo, 12);
        t_hi = SHISHUA_ALIGNR_EPI8(s_lo, s_hi, 12);

        state[4 * j + 2] = _mm_add_epi64(t_lo, u1_lo);
        state[4 * j + 3] = _mm_add_epi64(t_hi, u1_hi);

        // Merge lane 0 and lane 1
        // The first orthogonally grown piece evolving independently, XORed.
        output[2 * j + 0] = _mm_xor_si128(u0_lo, t_lo);
        output[2 * j + 1] = _mm_xor_si128(u0_hi, t_hi);
      }

      // The second orthogonally grown piece evolving independently, XORed.
      output[4] = _mm_xor_si128(state[0], state[6]);
      output[5] = _mm_xor_si128(state[1], state[7]);
      output[6] = _mm_xor_si128(state[4], state[2]);
      output[7] = _mm_xor_si128(state[5], state[3]);

      // Increment the counter
      counter_lo = _mm_add_epi64(counter_lo, increment_lo);
      counter_hi = _mm_add_epi64(counter_hi, increment_hi);
    }

    counter[0] = counter_lo;
    counter[1] = counter_hi;
  }

  prng_state(::std::array<uint64_t, 4> seed) {
    constexpr int ROUNDS = 13;
    constexpr int STEPS = 1;

    // Note: output is uninitialized at first, but since we pass NULL, its value
    // is initially ignored.
    counter[0] = _mm_setzero_si128();
    counter[1] = _mm_setzero_si128();

    // Diffuse first two seed elements in s0, then the last two. Same for s1.
    // We must keep half of the state unchanged so users cannot set a bad state.
    __m128i seed_0 = SHISHUA_CVTSI64_SI128(seed[0]);
    __m128i seed_1 = SHISHUA_CVTSI64_SI128(seed[1]);
    __m128i seed_2 = SHISHUA_CVTSI64_SI128(seed[2]);
    __m128i seed_3 = SHISHUA_CVTSI64_SI128(seed[3]);
    state[0] = _mm_xor_si128(seed_0, _mm_loadu_si128((__m128i *)&phi[0]));
    state[1] = _mm_xor_si128(seed_1, _mm_loadu_si128((__m128i *)&phi[2]));
    state[2] = _mm_xor_si128(seed_2, _mm_loadu_si128((__m128i *)&phi[4]));
    state[3] = _mm_xor_si128(seed_3, _mm_loadu_si128((__m128i *)&phi[6]));
    state[4] = _mm_xor_si128(seed_2, _mm_loadu_si128((__m128i *)&phi[8]));
    state[5] = _mm_xor_si128(seed_3, _mm_loadu_si128((__m128i *)&phi[10]));
    state[6] = _mm_xor_si128(seed_0, _mm_loadu_si128((__m128i *)&phi[12]));
    state[7] = _mm_xor_si128(seed_1, _mm_loadu_si128((__m128i *)&phi[14]));

    for (int i = 0; i < ROUNDS; i++) {
      block(0, 128 * STEPS);
      state[0] = output[6];
      state[1] = output[7];
      state[2] = output[4];
      state[3] = output[5];
      state[4] = output[2];
      state[5] = output[3];
      state[6] = output[0];
      state[7] = output[1];
    }
  }
};

}  // namespace detail
}  // namespace shishua

#elif SHISHUA_TARGET == SHISHUA_TARGET_NEON

#include <arm_neon.h>

#if defined(__GNUC__) && \
    (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#define SHISHUA_VSETQ_N_U64(a, b) (__extension__(uint64x2_t){a, b})
#else
#define SHISHUA_VSETQ_N_U64(a, b) vcombine_u64(vdup_n_u64(a), vdup_n_u64(b))
#endif
// To hide the vreinterpret ritual.
#define SHISHUA_VEXTQ_U8(Rn, Rm, Imm) \
  vreinterpretq_u64_u8(               \
      vextq_u8(vreinterpretq_u8_u64(Rn), vreinterpretq_u8_u64(Rm), (Imm)))

namespace shishua {
namespace detail {

class prng_state {
  uint64x2_t state[8];
  uint64x2_t output[8];
  uint64x2_t counter[2];

 public:
  void block(uint8_t *buf, size_t size) {
    uint8_t *b = buf;
    uint64x2_t counter_lo = counter[0], counter_hi = counter[1];
    // The counter is not necessary to beat PractRand.
    // It sets a lower bound of 2^71 bytes = 2 ZiB to the period,
    // or about 7 millenia at 10 GiB/s.
    // The increments are picked as odd numbers,
    // since only coprimes of the base cover the full cycle,
    // and all odd numbers are coprime of 2.
    // I use different odd numbers for each 64-bit chunk
    // for a tiny amount of variation stirring.
    // I used the smallest odd numbers to avoid having a magic number.
    uint64x2_t increment_lo = SHISHUA_VSETQ_N_U64(7, 5);
    uint64x2_t increment_hi = SHISHUA_VSETQ_N_U64(3, 1);
    // TODO: consider adding proper uneven write handling
    assert((size % 128 == 0) && "buf's size must be a multiple of 128 bytes.");

    for (size_t i = 0; i < size; i += 128) {
      // Write the current output block to state if it is not NULL
      if (buf != NULL) {
        for (size_t j = 0; j < 8; j++) {
          vst1q_u8(b, vreinterpretq_u8_u64(output[j]));
          b += 16;
        }
      }
      // NEON has less register pressure than SSE2, but we reroll it anyways for
      // code size.
      for (size_t j = 0; j < 2; j++) {
        uint64x2_t s0_lo = state[j * 4 + 0], s0_hi = state[j * 4 + 1],
                   s1_lo = state[j * 4 + 2], s1_hi = state[j * 4 + 3], t0_lo,
                   t0_hi, t1_lo, t1_hi, u_lo, u_hi;

        // I apply the counter to s1,
        // since it is the one whose shift loses most entropy.
        s1_lo = vaddq_u64(s1_lo, counter_lo);
        s1_hi = vaddq_u64(s1_hi, counter_hi);

        // The following shuffles move weak (low-diffusion) 32-bit parts of
        // 64-bit additions to strong positions for enrichment. The low 32-bit
        // part of a 64-bit chunk never moves to the same 64-bit chunk as its
        // high part. They do not remain in the same chunk. Each part eventually
        // reaches all positions ringwise: A to B, B to C, …, H to A. You may
        // notice that they are simply 256-bit rotations (96 and 160). Note:
        // This:
        //   x = (y << 96) | (y >> 160)
        // can be rewritten as this
        //   x_lo = (y_lo << 96) | (y_hi >> 32)
        //   x_hi = (y_hi << 96) | (y_lo >> 32)
        // which we can do with 2 vext.8 instructions.
        t0_lo = SHISHUA_VEXTQ_U8(s0_hi, s0_lo, 4);
        t0_hi = SHISHUA_VEXTQ_U8(s0_lo, s0_hi, 4);
        t1_lo = SHISHUA_VEXTQ_U8(s1_lo, s1_hi, 12);
        t1_hi = SHISHUA_VEXTQ_U8(s1_hi, s1_lo, 12);

        // SIMD does not support rotations. Shift is the next best thing to
        // entangle bits with other 64-bit positions. We must shift by an odd
        // number so that each bit reaches all 64-bit positions, not just half.
        // We must lose bits of information, so we minimize it: 1 and 3. We use
        // different shift values to increase divergence between the two sides.
        // We use rightward shift because the rightmost bits have the least
        // diffusion in addition (the low bit is just a XOR of the low bits).
        u_lo = vshrq_n_u64(s0_lo, 1);
        u_hi = vshrq_n_u64(s0_hi, 1);
#if defined(__clang__)
        // UGLY HACK: Clang enjoys merging the above statements with the vadds
        // below into vsras. This is dumb, as it still needs to do the original
        // vshr for the xor mix, causing it to shift twice. This makes Clang
        // assume that this line has side effects, preventing the combination
        // and speeding things up significantly.
        __asm__("" : "+w"(u_lo), "+w"(u_hi));
#endif

        // Addition is the main source of diffusion.
        // Storing the output in the state keeps that diffusion permanently.
        state[4 * j + 0] = vaddq_u64(t0_lo, u_lo);
        state[4 * j + 1] = vaddq_u64(t0_hi, u_hi);
        // Use vsra here directly.
        state[4 * j + 2] = vsraq_n_u64(t1_lo, s1_lo, 3);
        state[4 * j + 3] = vsraq_n_u64(t1_hi, s1_hi, 3);

        // The first orthogonally grown pieces evolving independently, XORed.
        output[2 * j + 0] = veorq_u64(u_lo, t1_lo);
        output[2 * j + 1] = veorq_u64(u_hi, t1_hi);
      }
      // The second orthogonally grown piece evolving independently, XORed.
      output[4] = veorq_u64(state[0], state[6]);
      output[5] = veorq_u64(state[1], state[7]);

      output[6] = veorq_u64(state[2], state[4]);
      output[7] = veorq_u64(state[3], state[5]);

      counter_lo = vaddq_u64(counter_lo, increment_lo);
      counter_hi = vaddq_u64(counter_hi, increment_hi);
    }
    counter[0] = counter_lo;
    counter[1] = counter_hi;
  }

  prng_state(::std::array<uint64_t, 4> seed) {
    constexpr int ROUNDS = 13;
    constexpr int STEPS = 1;

    counter[0] = vdupq_n_u64(0);
    counter[1] = vdupq_n_u64(0);
    // Diffuse first two seed elements in s0, then the last two. Same for s1.
    // We must keep half of the state unchanged so users cannot set a bad state.
    uint64x2_t seed_0 = SHISHUA_VSETQ_N_U64(seed[0], 0);
    uint64x2_t seed_1 = SHISHUA_VSETQ_N_U64(seed[1], 0);
    uint64x2_t seed_2 = SHISHUA_VSETQ_N_U64(seed[2], 0);
    uint64x2_t seed_3 = SHISHUA_VSETQ_N_U64(seed[3], 0);
    state[0] = veorq_u64(seed_0, vld1q_u64(&phi[0]));
    state[1] = veorq_u64(seed_1, vld1q_u64(&phi[2]));
    state[2] = veorq_u64(seed_2, vld1q_u64(&phi[4]));
    state[3] = veorq_u64(seed_3, vld1q_u64(&phi[6]));
    state[4] = veorq_u64(seed_2, vld1q_u64(&phi[8]));
    state[5] = veorq_u64(seed_3, vld1q_u64(&phi[10]));
    state[6] = veorq_u64(seed_0, vld1q_u64(&phi[12]));
    state[7] = veorq_u64(seed_1, vld1q_u64(&phi[14]));

    for (int i = 0; i < ROUNDS; i++) {
      block(0, 128 * STEPS);
      state[0] = output[6];
      state[1] = output[7];
      state[2] = output[4];
      state[3] = output[5];
      state[4] = output[2];
      state[5] = output[3];
      state[6] = output[0];
      state[7] = output[1];
    }
  }
};

}  // namespace detail
}  // namespace shishua

#else  // SHISHUA_TARGET == SHISHUA_TARGET_SCALAR

#include <cstring>

namespace shishua {
namespace detail {

// Portable scalar implementation of shishua.
// Designed to balance performance and code size.

// Writes a 64-bit little endian integer to dst
static inline void prng_write_le64(void *dst, uint64_t val) {
  // Define to write in native endianness with memcpy
  // Also, use memcpy on known little endian setups.
#if defined(SHISHUA_NATIVE_ENDIAN) || defined(_WIN32) ||                      \
    (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || \
    defined(__LITTLE_ENDIAN__)
  memcpy(dst, &val, sizeof(uint64_t));
#else
  // Byteshift write.
  uint8_t *d = (uint8_t *)dst;
  for (size_t i = 0; i < 8; i++) {
    d[i] = (uint8_t)(val & 0xff);
    val >>= 8;
  }
#endif
}

// Note: While it is an array, a "lane" refers to 4 consecutive uint64_t.
class prng_state {
  uint64_t state[16];   // 4 lanes
  uint64_t output[16];  // 4 lanes, 2 parts
  uint64_t counter[4];  // 1 lane

 public:
  void block(uint8_t *buf, size_t size) {
    uint8_t *b = buf;
    assert((size % 128 == 0) && "buf's size must be a multiple of 128 bytes.");

    for (size_t i = 0; i < size; i += 128) {
      // Write the current output block to state if it is not NULL
      if (buf != 0) {
        for (size_t j = 0; j < 16; j++) {
          prng_write_le64(b, output[j]);
          b += 8;
        }
      }
      // Similar to SSE, use fixed iteration loops to reduce code complexity
      // and allow the compiler more control over optimization.
      for (size_t j = 0; j < 2; j++) {
        // I don't want to type this 15 times.
        uint64_t *s = &state[j * 8];   // 2 lanes
        uint64_t *o = &output[j * 4];  // 1 lane
        uint64_t t[8];                 // temp buffer

        // I apply the counter to s1,
        // since it is the one whose shift loses most entropy.
        for (size_t k = 0; k < 4; k++) {
          s[k + 4] += counter[k];
        }

        // The following shuffles move weak (low-diffusion) 32-bit parts of
        // 64-bit additions to strong positions for enrichment. The low 32-bit
        // part of a 64-bit chunk never moves to the same 64-bit chunk as its
        // high part. They do not remain in the same chunk. Each part eventually
        // reaches all positions ringwise: A to B, B to C, …, H to A.
        //
        // You may notice that they are simply 256-bit rotations (96 and 160):
        //
        //   t0 = (s0 <<  96) | (s0 >> (256 -  96));
        //   t1 = (s1 << 160) | (s1 >> (256 - 160));
        //
        // The easiest way to do this would be to cast s and t to uint32_t *
        // and operate on them that way.
        //
        //   uint32_t *t0_32 = (uint32_t *)t0, *t1_32 = (uint32_t *)t1;
        //   uint32_t *s0_32 = (uint32_t *)s0, *s1_32 = (uint32_t *)s1;
        //   for (size_t k = 0; k < 4; k++) {
        //     t0_32[k] = s0_32[(k + 5) % 8];
        //     t1_32[k] = s1_32[(k + 3) % 8];
        //   }
        //
        // This is pretty, but it violates strict aliasing and relies on little
        // endian data layout.
        //
        // A common workaround to strict aliasing would be to use memcpy:
        //
        //   // legal casts
        //   unsigned char *t8 = (unsigned char *)t;
        //   unsigned char *s8 = (unsigned char *)s;
        //   memcpy(&t8[0], &s8[20], 32 - 20);
        //   memcpy(&t8[32 - 20], &s8[0], 20);
        //
        // However, this still doesn't fix the endianness issue, and is very
        // ugly.
        //
        // The only known solution which doesn't rely on endianness is to
        // read two 64-bit integers and do a funnel shift.

        // Lookup table for the _offsets_ in the shuffle. Even lanes rotate
        // by 5, odd lanes rotate by 3.
        // If it were by 32-bit lanes, it would be
        // { 5,6,7,0,1,2,3,4, 11,12,13,14,15,8,9,10 }
        const uint8_t shuf_offsets[16] = {2, 3, 0, 1, 5, 6, 7, 4,   // left
                                          3, 0, 1, 2, 6, 7, 4, 5};  // right
        for (size_t k = 0; k < 8; k++) {
          t[k] = (s[shuf_offsets[k]] >> 32) | (s[shuf_offsets[k + 8]] << 32);
        }

        for (size_t k = 0; k < 4; k++) {
          // SIMD does not support rotations. Shift is the next best thing to
          // entangle bits with other 64-bit positions. We must shift by an odd
          // number so that each bit reaches all 64-bit positions, not just
          // half. We must lose bits of information, so we minimize it: 1 and 3.
          // We use different shift values to increase divergence between the
          // two sides. We use rightward shift because the rightmost bits have
          // the least diffusion in addition (the low bit is just a XOR of the
          // low bits).
          uint64_t u_lo = s[k + 0] >> 1;
          uint64_t u_hi = s[k + 4] >> 3;

          // Addition is the main source of diffusion.
          // Storing the output in the state keeps that diffusion permanently.
          s[k + 0] = u_lo + t[k + 0];
          s[k + 4] = u_hi + t[k + 4];

          // The first orthogonally grown piece evolving independently, XORed.
          o[k] = u_lo ^ t[k + 4];
        }
      }

      // Merge together.
      for (size_t j = 0; j < 4; j++) {
        // The second orthogonally grown piece evolving independently, XORed.
        output[j + 8] = state[j + 0] ^ state[j + 12];
        output[j + 12] = state[j + 8] ^ state[j + 4];
        // The counter is not necessary to beat PractRand.
        // It sets a lower bound of 2^71 bytes = 2 ZiB to the period,
        // or about 7 millenia at 10 GiB/s.
        // The increments are picked as odd numbers,
        // since only coprimes of the base cover the full cycle,
        // and all odd numbers are coprime of 2.
        // I use different odd numbers for each 64-bit chunk
        // for a tiny amount of variation stirring.
        // I used the smallest odd numbers to avoid having a magic number.
        //
        // For the scalar version, we calculate this dynamically, as it is
        // simple enough.
        counter[j] += 7 - (j * 2);  // 7, 5, 3, 1
      }
    }
  }

  prng_state(::std::array<uint64_t, 4> seed) {
    constexpr int STEPS = 1;
    constexpr int ROUNDS = 13;

    // Diffuse first two seed elements in s0, then the last two. Same for s1.
    // We must keep half of the state unchanged so users cannot set a bad state.
    memcpy(state, phi, sizeof(phi));
    for (size_t i = 0; i < 4; i++) {
      state[i * 2 + 0] ^= seed[i];            // { s0,0,s1,0,s2,0,s3,0 }
      state[i * 2 + 8] ^= seed[(i + 2) % 4];  // { s2,0,s3,0,s0,0,s1,0 }
    }
    for (size_t i = 0; i < ROUNDS; i++) {
      block(0, 128 * STEPS);
      for (size_t j = 0; j < 4; j++) {
        state[j + 0] = output[j + 12];
        state[j + 4] = output[j + 8];
        state[j + 8] = output[j + 4];
        state[j + 12] = output[j + 0];
      }
    }
  }
};

}  // namespace detail
}  // namespace shishua

#endif  // SHISHUA_TARGET == SHISHUA_TARGET_SCALAR

namespace shishua {

template <size_t BLOCK_SIZE = 32>
class prng {
  detail::prng_state internal_state;
  uint64_t block[BLOCK_SIZE];
  uint64_t *cur;

  void refill() {
    internal_state.block(reinterpret_cast<uint8_t *>(&block[0]), sizeof(block));
    cur = block;
  }

 public:
  inline uint64 next() {
    if (cur == block + BLOCK_SIZE) {
      refill();
    }
    return *cur++;
  }

  prng(std::array<uint64_t, 4> seed) : internal_state(seed) { refill(); }
};

}  // namespace shishua
#endif  // SHISHUA_SCALAR_H
