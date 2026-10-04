#include <iostream>
#include <vector>
#include <array>
#include <string>
#include <chrono>
#include <cassert>
#include <iomanip>
#include "../src/crypto/AES256GCM.hpp"

// Convert hex string to vector of bytes
std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string bytesToHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

void testNISTVector() {
    std::cout << "[TEST 1] NIST SP 800-38D AES-256-GCM Known Answer Test..." << std::endl;
    // NIST CAVP Test Vector for AES-256-GCM
    // Key: 256-bit all zeroes
    std::vector<uint8_t> key = hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    // IV: 96-bit all zeroes
    std::vector<uint8_t> iv  = hexToBytes("000000000000000000000000");
    // Plaintext: empty
    std::vector<uint8_t> pt  = {};
    // Expected Tag for empty plaintext with key 0 and IV 0: 530f8afbc74536b9a963b4f1c4cb738b
    std::string expectedTagHex = "530f8afbc74536b9a963b4f1c4cb738b";

    std::vector<uint8_t> ct(pt.size());
    uint8_t tag[16] = {0};

    crypto::AES256GCM::encrypt(key.data(), iv.data(), pt.data(), pt.size(), ct.data(), tag);
    std::string actualTagHex = bytesToHex(tag, 16);

    assert(actualTagHex == expectedTagHex);
    std::cout << "  -> PASS: NIST Empty PT Tag = " << actualTagHex << std::endl;

    // Test with 64-byte payload
    std::string testMsg = "Systems Engineering at FAANG requires high-performance C++20!";
    std::vector<uint8_t> pt2(testMsg.begin(), testMsg.end());
    std::vector<uint8_t> ct2(pt2.size());
    uint8_t tag2[16] = {0};

    crypto::AES256GCM::encrypt(key.data(), iv.data(), pt2.data(), pt2.size(), ct2.data(), tag2);
    
    // Decrypt and verify
    std::vector<uint8_t> decrypted(pt2.size());
    crypto::AES256GCM::decrypt(key.data(), iv.data(), ct2.data(), ct2.size(), tag2, decrypted.data());

    std::string decMsg(decrypted.begin(), decrypted.end());
    assert(decMsg == testMsg);
    std::cout << "  -> PASS: Roundtrip Encrypt/Decrypt matches plaintext." << std::endl;
}

void testTamperDetection() {
    std::cout << "[TEST 2] Cryptographic Integrity & Anti-Tamper Verification..." << std::endl;
    std::array<uint8_t, 32> key{};
    crypto::AES256GCM::generateRandomBytes(key.data(), key.size());
    std::array<uint8_t, 12> iv{};
    crypto::AES256GCM::generateRandomBytes(iv.data(), iv.size());

    std::string secret = "Confidential Banking Record: Transfer $1,000,000 to Account #12345";
    std::vector<uint8_t> ct(secret.size());
    uint8_t tag[16] = {0};

    crypto::AES256GCM::encrypt(key.data(), iv.data(), reinterpret_cast<const uint8_t*>(secret.data()), secret.size(), ct.data(), tag);

    // 1. Bit-flip attack on ciphertext
    ct[5] ^= 0x01; // Tamper with 1 bit
    std::vector<uint8_t> decrypted(secret.size());

    bool exceptionCaught = false;
    try {
        crypto::AES256GCM::decrypt(key.data(), iv.data(), ct.data(), ct.size(), tag, decrypted.data());
    } catch (const crypto::AuthenticationFailedException& ex) {
        exceptionCaught = true;
    }
    assert(exceptionCaught);
    std::cout << "  -> PASS: Bit-flip on ciphertext successfully rejected by AEAD tag." << std::endl;

    // 2. Restore ciphertext, tamper with tag
    ct[5] ^= 0x01;
    tag[0] ^= 0x80;
    exceptionCaught = false;
    try {
        crypto::AES256GCM::decrypt(key.data(), iv.data(), ct.data(), ct.size(), tag, decrypted.data());
    } catch (const crypto::AuthenticationFailedException& ex) {
        exceptionCaught = true;
    }
    assert(exceptionCaught);
    std::cout << "  -> PASS: Tampered authentication tag successfully rejected." << std::endl;
}

void testKeyDerivation() {
    std::cout << "[TEST 3] PBKDF2-HMAC-SHA256 Key Derivation..." << std::endl;
    std::string passphrase = "MySuperSecurePassword@2026";
    std::array<uint8_t, 16> salt{};
    crypto::AES256GCM::generateRandomBytes(salt.data(), salt.size());

    auto key1 = crypto::AES256GCM::deriveKey(passphrase, salt, 10000);
    auto key2 = crypto::AES256GCM::deriveKey(passphrase, salt, 10000);
    assert(key1 == key2);
    std::cout << "  -> PASS: Deterministic 256-bit key derivation verified." << std::endl;
}

void benchmarkThroughput() {
    std::cout << "[TEST 4] Hardware-Accelerated Throughput Benchmark..." << std::endl;
    bool hasAES = crypto::AES256GCM::hasHardwareAESNI();
    std::cout << "  -> CPU AES-NI + PCLMULQDQ Supported: " << (hasAES ? "YES (Hardware Accelerated)" : "NO") << std::endl;

    const size_t DATA_SIZE = 64 * 1024 * 1024; // 64 MB
    std::vector<uint8_t> plaintext(DATA_SIZE, 0x5A);
    std::vector<uint8_t> ciphertext(DATA_SIZE);
    uint8_t tag[16];
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 12> iv{};

    auto startEnc = std::chrono::high_resolution_clock::now();
    crypto::AES256GCM::encrypt(key.data(), iv.data(), plaintext.data(), DATA_SIZE, ciphertext.data(), tag);
    auto endEnc = std::chrono::high_resolution_clock::now();

    double encSeconds = std::chrono::duration<double>(endEnc - startEnc).count();
    double encThroughputGBs = (static_cast<double>(DATA_SIZE) / (1024.0 * 1024.0 * 1024.0)) / encSeconds;
    double encThroughputMBs = (static_cast<double>(DATA_SIZE) / (1024.0 * 1024.0)) / encSeconds;

    std::cout << "  -> Encryption: " << DATA_SIZE / (1024 * 1024) << " MB encrypted in " 
              << std::fixed << std::setprecision(3) << (encSeconds * 1000.0) << " ms (" 
              << encThroughputMBs << " MB/s | " << encThroughputGBs << " GB/s)" << std::endl;

    auto startDec = std::chrono::high_resolution_clock::now();
    crypto::AES256GCM::decrypt(key.data(), iv.data(), ciphertext.data(), DATA_SIZE, tag, plaintext.data());
    auto endDec = std::chrono::high_resolution_clock::now();

    double decSeconds = std::chrono::duration<double>(endDec - startDec).count();
    double decThroughputMBs = (static_cast<double>(DATA_SIZE) / (1024.0 * 1024.0)) / decSeconds;

    std::cout << "  -> Decryption: " << DATA_SIZE / (1024 * 1024) << " MB decrypted & verified in " 
              << (decSeconds * 1000.0) << " ms (" << decThroughputMBs << " MB/s)" << std::endl;
}

int main() {
    std::cout << "=========================================================" << std::endl;
    std::cout << "  Parallel File Encrypter: AES-256-GCM Crypto Test Suite " << std::endl;
    std::cout << "=========================================================" << std::endl;

    testNISTVector();
    testTamperDetection();
    testKeyDerivation();
    benchmarkThroughput();

    std::cout << "\n>>> ALL CRYPTOGRAPHIC TESTS PASSED SUCCESSFULLY! <<<" << std::endl;
    return 0;
}
