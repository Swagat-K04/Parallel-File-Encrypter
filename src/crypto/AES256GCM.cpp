#include "AES256GCM.hpp"
#include <cstring>
#include <random>
#include <algorithm>
#include <immintrin.h>
#include <wmmintrin.h>
#include <tmmintrin.h>
#include <cpuid.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC target("ssse3,sse4.1,aes,pclmul")
#endif

namespace crypto {

// ============================================================================
// 1. CPUID Feature Detection
// ============================================================================
bool AES256GCM::hasHardwareAESNI() {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        bool hasAES = (ecx & (1 << 25)) != 0;
        bool hasPCLMUL = (ecx & (1 << 1)) != 0;
        return hasAES && hasPCLMUL;
    }
    return false;
}

// ============================================================================
// 2. Cryptographically Secure Random Number Generator & Constant Time Compare
// ============================================================================
void AES256GCM::generateRandomBytes(uint8_t* out, size_t length) {
    std::random_device rd;
    size_t i = 0;
    while (i + sizeof(unsigned int) <= length) {
        unsigned int val = rd();
        std::memcpy(out + i, &val, sizeof(unsigned int));
        i += sizeof(unsigned int);
    }
    if (i < length) {
        unsigned int val = rd();
        std::memcpy(out + i, &val, length - i);
    }
}

bool AES256GCM::constantTimeEquals(const uint8_t* a, const uint8_t* b, size_t length) {
    uint8_t result = 0;
    for (size_t i = 0; i < length; ++i) {
        result |= (a[i] ^ b[i]);
    }
    return result == 0;
}

// ============================================================================
// 3. SHA-256 & PBKDF2-HMAC-SHA256 Implementation
// ============================================================================
namespace {

struct SHA256Context {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
};

static inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(data[i * 4]) << 24) |
               (static_cast<uint32_t>(data[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(data[i * 4 + 2]) << 8) |
               (static_cast<uint32_t>(data[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256_init(SHA256Context* ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

void sha256_update(SHA256Context* ctx, const uint8_t* data, size_t len) {
    size_t buffer_idx = (ctx->count >> 3) & 63;
    ctx->count += (len << 3);

    size_t part_len = 64 - buffer_idx;
    size_t i = 0;

    if (len >= part_len) {
        std::memcpy(&ctx->buffer[buffer_idx], data, part_len);
        sha256_transform(ctx->state, ctx->buffer);
        for (i = part_len; i + 63 < len; i += 64) {
            sha256_transform(ctx->state, &data[i]);
        }
        buffer_idx = 0;
    }
    std::memcpy(&ctx->buffer[buffer_idx], &data[i], len - i);
}

void sha256_final(SHA256Context* ctx, uint8_t digest[32]) {
    static const uint8_t padding[64] = { 0x80 };
    size_t pad_len = ((ctx->count >> 3) & 63) < 56 ? (56 - ((ctx->count >> 3) & 63)) : (120 - ((ctx->count >> 3) & 63));
    uint8_t count_bytes[8];
    for (int i = 0; i < 8; ++i) {
        count_bytes[i] = static_cast<uint8_t>(ctx->count >> ((7 - i) * 8));
    }
    sha256_update(ctx, padding, pad_len);
    sha256_update(ctx, count_bytes, 8);

    for (int i = 0; i < 8; ++i) {
        digest[i * 4]     = static_cast<uint8_t>(ctx->state[i] >> 24);
        digest[i * 4 + 1] = static_cast<uint8_t>(ctx->state[i] >> 16);
        digest[i * 4 + 2] = static_cast<uint8_t>(ctx->state[i] >> 8);
        digest[i * 4 + 3] = static_cast<uint8_t>(ctx->state[i]);
    }
}

void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t out[32]) {
    uint8_t k[64] = {0};
    if (key_len > 64) {
        SHA256Context ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, k);
    } else {
        std::memcpy(k, key, key_len);
    }

    uint8_t k_ipad[64], k_opad[64];
    for (int i = 0; i < 64; ++i) {
        k_ipad[i] = k[i] ^ 0x36;
        k_opad[i] = k[i] ^ 0x5c;
    }

    uint8_t inner_hash[32];
    SHA256Context ctx_inner;
    sha256_init(&ctx_inner);
    sha256_update(&ctx_inner, k_ipad, 64);
    sha256_update(&ctx_inner, msg, msg_len);
    sha256_final(&ctx_inner, inner_hash);

    SHA256Context ctx_outer;
    sha256_init(&ctx_outer);
    sha256_update(&ctx_outer, k_opad, 64);
    sha256_update(&ctx_outer, inner_hash, 32);
    sha256_final(&ctx_outer, out);
}

} // anonymous namespace

std::array<uint8_t, KEY_SIZE> AES256GCM::deriveKey(
    std::string_view passphrase, 
    const std::array<uint8_t, SALT_SIZE>& salt, 
    uint32_t iterations
) {
    std::array<uint8_t, KEY_SIZE> derived_key{};
    // PBKDF2-HMAC-SHA256 for 1 block (32 bytes)
    uint8_t salt_plus_block[SALT_SIZE + 4];
    std::memcpy(salt_plus_block, salt.data(), SALT_SIZE);
    salt_plus_block[SALT_SIZE] = 0;
    salt_plus_block[SALT_SIZE + 1] = 0;
    salt_plus_block[SALT_SIZE + 2] = 0;
    salt_plus_block[SALT_SIZE + 3] = 1; // Block index 1

    uint8_t u[32], t[32];
    hmac_sha256(
        reinterpret_cast<const uint8_t*>(passphrase.data()), 
        passphrase.size(), 
        salt_plus_block, 
        sizeof(salt_plus_block), 
        u
    );
    std::memcpy(t, u, 32);

    for (uint32_t iter = 1; iter < iterations; ++iter) {
        hmac_sha256(
            reinterpret_cast<const uint8_t*>(passphrase.data()), 
            passphrase.size(), 
            u, 
            32, 
            u
        );
        for (int b = 0; b < 32; ++b) {
            t[b] ^= u[b];
        }
    }
    std::memcpy(derived_key.data(), t, KEY_SIZE);
    return derived_key;
}

// ============================================================================
// 4. AES-NI Key Schedule (256-bit, 14 rounds)
// ============================================================================
namespace {

template<int rcon>
__attribute__((always_inline))
static inline void aes256_key_expansion_assist(__m128i &key1, __m128i &key2) {
    __m128i t1, t2, t4;
    t4 = _mm_aeskeygenassist_si128(key2, rcon);
    t2 = _mm_shuffle_epi32(t4, 0xff);
    t1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
    t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));
    t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));
    key1 = _mm_xor_si128(t1, t2);

    t4 = _mm_aeskeygenassist_si128(key1, 0x00);
    t2 = _mm_shuffle_epi32(t4, 0xaa);
    t1 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
    t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));
    t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));
    key2 = _mm_xor_si128(t1, t2);
}

struct AES256RoundKeys {
    __m128i rk[15]; // 14 rounds for AES-256
};

void aes256_init_round_keys(const uint8_t* key, AES256RoundKeys& keys) {
    __m128i key1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
    __m128i key2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key + 16));

    keys.rk[0] = key1;
    keys.rk[1] = key2;

    aes256_key_expansion_assist<0x01>(key1, key2); keys.rk[2] = key1; keys.rk[3] = key2;
    aes256_key_expansion_assist<0x02>(key1, key2); keys.rk[4] = key1; keys.rk[5] = key2;
    aes256_key_expansion_assist<0x04>(key1, key2); keys.rk[6] = key1; keys.rk[7] = key2;
    aes256_key_expansion_assist<0x08>(key1, key2); keys.rk[8] = key1; keys.rk[9] = key2;
    aes256_key_expansion_assist<0x10>(key1, key2); keys.rk[10] = key1; keys.rk[11] = key2;
    aes256_key_expansion_assist<0x20>(key1, key2); keys.rk[12] = key1; keys.rk[13] = key2;

    __m128i t4 = _mm_aeskeygenassist_si128(key2, 0x40);
    __m128i t2 = _mm_shuffle_epi32(t4, 0xff);
    __m128i t1 = _mm_xor_si128(key1, _mm_slli_si128(key1, 4));
    t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));
    t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));
    keys.rk[14] = _mm_xor_si128(t1, t2);
}

__attribute__((always_inline))
static inline __m128i aes256_encrypt_block(__m128i block, const AES256RoundKeys& keys) {
    block = _mm_xor_si128(block, keys.rk[0]);
    block = _mm_aesenc_si128(block, keys.rk[1]);
    block = _mm_aesenc_si128(block, keys.rk[2]);
    block = _mm_aesenc_si128(block, keys.rk[3]);
    block = _mm_aesenc_si128(block, keys.rk[4]);
    block = _mm_aesenc_si128(block, keys.rk[5]);
    block = _mm_aesenc_si128(block, keys.rk[6]);
    block = _mm_aesenc_si128(block, keys.rk[7]);
    block = _mm_aesenc_si128(block, keys.rk[8]);
    block = _mm_aesenc_si128(block, keys.rk[9]);
    block = _mm_aesenc_si128(block, keys.rk[10]);
    block = _mm_aesenc_si128(block, keys.rk[11]);
    block = _mm_aesenc_si128(block, keys.rk[12]);
    block = _mm_aesenc_si128(block, keys.rk[13]);
    return _mm_aesenclast_si128(block, keys.rk[14]);
}

// Byte swap helper for 128-bit big-endian counter
static inline __m128i bswap_epi128(__m128i val) {
    static const __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    return _mm_shuffle_epi8(val, BSWAP_MASK);
}

// ============================================================================
// 5. Hardware GHASH Implementation via PCLMULQDQ
// ============================================================================
__attribute__((always_inline))
static inline __m128i ghash_mul(__m128i a, __m128i b) {
    __m128i tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6;
    tmp0 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp1 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp2 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp3 = _mm_clmulepi64_si128(a, b, 0x11);

    tmp1 = _mm_xor_si128(tmp1, tmp2);
    tmp2 = _mm_slli_si128(tmp1, 8);
    tmp1 = _mm_srli_si128(tmp1, 8);
    tmp0 = _mm_xor_si128(tmp0, tmp2);
    tmp3 = _mm_xor_si128(tmp3, tmp1);

    // Galois reduction modulo x^128 + x^7 + x^2 + x + 1
    tmp4 = _mm_srli_epi32(tmp0, 31);
    tmp5 = _mm_srli_epi32(tmp3, 31);
    tmp0 = _mm_slli_epi32(tmp0, 1);
    tmp3 = _mm_slli_epi32(tmp3, 1);

    tmp4 = _mm_slli_si128(tmp4, 4);
    tmp0 = _mm_or_si128(tmp0, tmp4);
    tmp5 = _mm_slli_si128(tmp5, 4);
    tmp3 = _mm_or_si128(tmp3, tmp5);

    tmp6 = _mm_clmulepi64_si128(tmp0, _mm_set_epi32(0, 0, 0x00000001, 0xc2000000), 0x01);
    tmp0 = _mm_xor_si128(tmp0, _mm_slli_si128(tmp6, 8));
    tmp6 = _mm_clmulepi64_si128(tmp0, _mm_set_epi32(0, 0, 0x00000001, 0xc2000000), 0x00);
    return _mm_xor_si128(tmp3, tmp6);
}

} // anonymous namespace

// ============================================================================
// 6. Full AES-256-GCM Encrypt & Decrypt Routines
// ============================================================================
void AES256GCM::encrypt(
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* plaintext,
    size_t plaintext_len,
    uint8_t* ciphertext_out,
    uint8_t* tag_out,
    const uint8_t* aad,
    size_t aad_len
) {
    AES256RoundKeys round_keys;
    aes256_init_round_keys(key, round_keys);

    // Compute H = AES_K(0^128) for GHASH
    __m128i H = aes256_encrypt_block(_mm_setzero_si128(), round_keys);
    H = bswap_epi128(H);

    // Construct J0 = IV || 0^31 || 1
    uint8_t j0_buf[16] = {0};
    std::memcpy(j0_buf, iv, IV_SIZE);
    j0_buf[15] = 1;
    __m128i J0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(j0_buf));

    // Compute E_K(J0) for authentication tag masking
    __m128i tag_mask = aes256_encrypt_block(J0, round_keys);

    // CTR mode encryption starting at J0 + 1
    uint32_t counter = 2; // Big endian counter starts at 2
    size_t offset = 0;

    __m128i ctr_block = J0;

    while (offset + BLOCK_SIZE <= plaintext_len) {
        // Set counter in lower 32 bits (big-endian)
        uint8_t* ctr_ptr = reinterpret_cast<uint8_t*>(&ctr_block);
        ctr_ptr[12] = static_cast<uint8_t>(counter >> 24);
        ctr_ptr[13] = static_cast<uint8_t>(counter >> 16);
        ctr_ptr[14] = static_cast<uint8_t>(counter >> 8);
        ctr_ptr[15] = static_cast<uint8_t>(counter);
        counter++;

        __m128i key_stream = aes256_encrypt_block(ctr_block, round_keys);
        __m128i pt_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(plaintext + offset));
        __m128i ct_block = _mm_xor_si128(pt_block, key_stream);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(ciphertext_out + offset), ct_block);
        offset += BLOCK_SIZE;
    }

    if (offset < plaintext_len) {
        uint8_t* ctr_ptr = reinterpret_cast<uint8_t*>(&ctr_block);
        ctr_ptr[12] = static_cast<uint8_t>(counter >> 24);
        ctr_ptr[13] = static_cast<uint8_t>(counter >> 16);
        ctr_ptr[14] = static_cast<uint8_t>(counter >> 8);
        ctr_ptr[15] = static_cast<uint8_t>(counter);

        __m128i key_stream = aes256_encrypt_block(ctr_block, round_keys);
        uint8_t ks_buf[BLOCK_SIZE];
        _mm_storeu_si128(reinterpret_cast<__m128i*>(ks_buf), key_stream);

        for (size_t i = 0; offset + i < plaintext_len; ++i) {
            ciphertext_out[offset + i] = plaintext[offset + i] ^ ks_buf[i];
        }
    }

    // Compute GHASH over AAD and Ciphertext
    __m128i ghash_state = _mm_setzero_si128();

    // Process AAD
    size_t aad_offset = 0;
    while (aad_offset + BLOCK_SIZE <= aad_len) {
        __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(aad + aad_offset));
        ghash_state = _mm_xor_si128(ghash_state, bswap_epi128(block));
        ghash_state = ghash_mul(ghash_state, H);
        aad_offset += BLOCK_SIZE;
    }
    if (aad_offset < aad_len) {
        uint8_t pad_block[16] = {0};
        std::memcpy(pad_block, aad + aad_offset, aad_len - aad_offset);
        __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pad_block));
        ghash_state = _mm_xor_si128(ghash_state, bswap_epi128(block));
        ghash_state = ghash_mul(ghash_state, H);
    }

    // Process Ciphertext
    size_t ct_offset = 0;
    while (ct_offset + BLOCK_SIZE <= plaintext_len) {
        __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ciphertext_out + ct_offset));
        ghash_state = _mm_xor_si128(ghash_state, bswap_epi128(block));
        ghash_state = ghash_mul(ghash_state, H);
        ct_offset += BLOCK_SIZE;
    }
    if (ct_offset < plaintext_len) {
        uint8_t pad_block[16] = {0};
        std::memcpy(pad_block, ciphertext_out + ct_offset, plaintext_len - ct_offset);
        __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pad_block));
        ghash_state = _mm_xor_si128(ghash_state, bswap_epi128(block));
        ghash_state = ghash_mul(ghash_state, H);
    }

    // Process Length Block: len(AAD) in bits (64b) || len(C) in bits (64b)
    uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8;
    uint64_t ct_bits = static_cast<uint64_t>(plaintext_len) * 8;
    uint8_t len_buf[16];
    for (int i = 0; i < 8; ++i) {
        len_buf[i] = static_cast<uint8_t>(aad_bits >> ((7 - i) * 8));
        len_buf[8 + i] = static_cast<uint8_t>(ct_bits >> ((7 - i) * 8));
    }
    __m128i len_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(len_buf));
    ghash_state = _mm_xor_si128(ghash_state, bswap_epi128(len_block));
    ghash_state = ghash_mul(ghash_state, H);

    // Tag = GHASH ^ E_K(J0)
    __m128i final_tag = _mm_xor_si128(bswap_epi128(ghash_state), tag_mask);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(tag_out), final_tag);
}

void AES256GCM::decrypt(
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* tag,
    uint8_t* plaintext_out,
    const uint8_t* aad,
    size_t aad_len
) {
    AES256RoundKeys round_keys;
    aes256_init_round_keys(key, round_keys);

    // Compute H = AES_K(0^128)
    __m128i H = aes256_encrypt_block(_mm_setzero_si128(), round_keys);
    H = bswap_epi128(H);

    // Construct J0
    uint8_t j0_buf[16] = {0};
    std::memcpy(j0_buf, iv, IV_SIZE);
    j0_buf[15] = 1;
    __m128i J0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(j0_buf));

    // Calculate GHASH over AAD and Ciphertext for validation
    __m128i ghash_state = _mm_setzero_si128();

    // Process AAD
    size_t aad_offset = 0;
    while (aad_offset + BLOCK_SIZE <= aad_len) {
        __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(aad + aad_offset));
        ghash_state = _mm_xor_si128(ghash_state, bswap_epi128(block));
        ghash_state = ghash_mul(ghash_state, H);
        aad_offset += BLOCK_SIZE;
    }
    if (aad_offset < aad_len) {
        uint8_t pad_block[16] = {0};
        std::memcpy(pad_block, aad + aad_offset, aad_len - aad_offset);
        __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pad_block));
        ghash_state = _mm_xor_si128(ghash_state, bswap_epi128(block));
        ghash_state = ghash_mul(ghash_state, H);
    }

    // Process Ciphertext
    size_t ct_offset = 0;
    while (ct_offset + BLOCK_SIZE <= ciphertext_len) {
        __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ciphertext + ct_offset));
        ghash_state = _mm_xor_si128(ghash_state, bswap_epi128(block));
        ghash_state = ghash_mul(ghash_state, H);
        ct_offset += BLOCK_SIZE;
    }
    if (ct_offset < ciphertext_len) {
        uint8_t pad_block[16] = {0};
        std::memcpy(pad_block, ciphertext + ct_offset, ciphertext_len - ct_offset);
        __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pad_block));
        ghash_state = _mm_xor_si128(ghash_state, bswap_epi128(block));
        ghash_state = ghash_mul(ghash_state, H);
    }

    // Length Block
    uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8;
    uint64_t ct_bits = static_cast<uint64_t>(ciphertext_len) * 8;
    uint8_t len_buf[16];
    for (int i = 0; i < 8; ++i) {
        len_buf[i] = static_cast<uint8_t>(aad_bits >> ((7 - i) * 8));
        len_buf[8 + i] = static_cast<uint8_t>(ct_bits >> ((7 - i) * 8));
    }
    __m128i len_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(len_buf));
    ghash_state = _mm_xor_si128(ghash_state, bswap_epi128(len_block));
    ghash_state = ghash_mul(ghash_state, H);

    __m128i tag_mask = aes256_encrypt_block(J0, round_keys);
    __m128i computed_tag = _mm_xor_si128(bswap_epi128(ghash_state), tag_mask);

    uint8_t comp_tag_buf[TAG_SIZE];
    _mm_storeu_si128(reinterpret_cast<__m128i*>(comp_tag_buf), computed_tag);

    // Constant-time tag check BEFORE decrypting/releasing plaintext
    if (!constantTimeEquals(comp_tag_buf, tag, TAG_SIZE)) {
        throw AuthenticationFailedException();
    }

    // CTR mode decryption
    uint32_t counter = 2;
    size_t offset = 0;
    __m128i ctr_block = J0;

    while (offset + BLOCK_SIZE <= ciphertext_len) {
        uint8_t* ctr_ptr = reinterpret_cast<uint8_t*>(&ctr_block);
        ctr_ptr[12] = static_cast<uint8_t>(counter >> 24);
        ctr_ptr[13] = static_cast<uint8_t>(counter >> 16);
        ctr_ptr[14] = static_cast<uint8_t>(counter >> 8);
        ctr_ptr[15] = static_cast<uint8_t>(counter);
        counter++;

        __m128i key_stream = aes256_encrypt_block(ctr_block, round_keys);
        __m128i ct_block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ciphertext + offset));
        __m128i pt_block = _mm_xor_si128(ct_block, key_stream);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(plaintext_out + offset), pt_block);
        offset += BLOCK_SIZE;
    }

    if (offset < ciphertext_len) {
        uint8_t* ctr_ptr = reinterpret_cast<uint8_t*>(&ctr_block);
        ctr_ptr[12] = static_cast<uint8_t>(counter >> 24);
        ctr_ptr[13] = static_cast<uint8_t>(counter >> 16);
        ctr_ptr[14] = static_cast<uint8_t>(counter >> 8);
        ctr_ptr[15] = static_cast<uint8_t>(counter);

        __m128i key_stream = aes256_encrypt_block(ctr_block, round_keys);
        uint8_t ks_buf[BLOCK_SIZE];
        _mm_storeu_si128(reinterpret_cast<__m128i*>(ks_buf), key_stream);

        for (size_t i = 0; offset + i < ciphertext_len; ++i) {
            plaintext_out[offset + i] = ciphertext[offset + i] ^ ks_buf[i];
        }
    }
}

} // namespace crypto
