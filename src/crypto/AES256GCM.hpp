#ifndef AES256_GCM_HPP
#define AES256_GCM_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>
#include <string>
#include <string_view>
#include <stdexcept>

namespace crypto {

// Constants for AES-256-GCM
constexpr size_t KEY_SIZE = 32;       // 256 bits
constexpr size_t IV_SIZE = 12;        // 96 bits recommended for GCM
constexpr size_t TAG_SIZE = 16;       // 128 bits authentication tag
constexpr size_t SALT_SIZE = 16;      // 128 bits salt for KDF
constexpr size_t BLOCK_SIZE = 16;     // 128 bits AES block
constexpr uint32_t MAGIC_HEADER = 0x31434E45; // "ENC1" in little-endian

class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& msg) : std::runtime_error(msg) {}
};

class AuthenticationFailedException : public CryptoException {
public:
    AuthenticationFailedException() 
        : CryptoException("Authentication tag validation failed: Data has been tampered with or corrupted.") {}
};

// Container header for encrypted files
#pragma pack(push, 1)
struct EncryptedContainerHeader {
    uint32_t magic;                    // 0x31434E45 ("ENC1")
    uint8_t salt[SALT_SIZE];           // Salt used for PBKDF2 key derivation
    uint8_t iv[IV_SIZE];               // Random 96-bit Nonce/IV
    uint8_t tag[TAG_SIZE];             // 128-bit GCM Authentication Tag
    uint64_t plaintext_size;           // Original plaintext size
};
#pragma pack(pop)

static_assert(sizeof(EncryptedContainerHeader) == 4 + 16 + 12 + 16 + 8, "Header packaging size mismatch");

class AES256GCM {
public:
    // Derives a 256-bit cryptographic key from a passphrase and salt using PBKDF2-HMAC-SHA256
    static std::array<uint8_t, KEY_SIZE> deriveKey(
        std::string_view passphrase, 
        const std::array<uint8_t, SALT_SIZE>& salt, 
        uint32_t iterations = 100000
    );

    // Generates cryptographically secure random bytes (e.g. for IV and Salt)
    static void generateRandomBytes(uint8_t* out, size_t length);

    // Constant-time memory comparison to prevent timing attacks
    static bool constantTimeEquals(const uint8_t* a, const uint8_t* b, size_t length);

    // Encrypts plaintext in-place or into an output buffer with AES-256-GCM
    // aad: Optional Additional Authenticated Data
    static void encrypt(
        const uint8_t* key,
        const uint8_t* iv,
        const uint8_t* plaintext,
        size_t plaintext_len,
        uint8_t* ciphertext_out,
        uint8_t* tag_out,
        const uint8_t* aad = nullptr,
        size_t aad_len = 0
    );

    // Decrypts ciphertext and verifies authentication tag
    // Throws AuthenticationFailedException if tag verification fails
    static void decrypt(
        const uint8_t* key,
        const uint8_t* iv,
        const uint8_t* ciphertext,
        size_t ciphertext_len,
        const uint8_t* tag,
        uint8_t* plaintext_out,
        const uint8_t* aad = nullptr,
        size_t aad_len = 0
    );

    // Checks if hardware AES-NI instructions are supported on the running CPU
    static bool hasHardwareAESNI();
};

} // namespace crypto

#endif // AES256_GCM_HPP
