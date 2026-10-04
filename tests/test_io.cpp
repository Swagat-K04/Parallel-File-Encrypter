#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <cassert>
#include <cstring>
#include <filesystem>
#include "../src/io/MemoryMappedFile.hpp"
#include "../src/io/FileProcessor.hpp"

namespace fs = std::filesystem;

void createTestFile(const std::string& path, size_t sizeInBytes, uint8_t pattern = 0xAB) {
    std::ofstream ofs(path, std::ios::binary);
    std::vector<uint8_t> buffer(64 * 1024, pattern);
    size_t written = 0;
    while (written < sizeInBytes) {
        size_t toWrite = std::min(buffer.size(), sizeInBytes - written);
        ofs.write(reinterpret_cast<const char*>(buffer.data()), toWrite);
        written += toWrite;
    }
}

void testZeroCopyMapping() {
    std::cout << "[TEST 1] Testing RAII MemoryMappedFile basic mapping & resizing..." << std::endl;
    std::string testPath = "test_mapped_file.bin";
    size_t testSize = 1024 * 1024; // 1 MB

    {
        io::MemoryMappedFile mfile;
        mfile.open(testPath, io::OpenMode::CreateOrResize, testSize);
        assert(mfile.isMapped());
        assert(mfile.size() == testSize);

        // Write sequential pattern directly into mapped virtual memory (Zero-Copy)
        for (size_t i = 0; i < testSize; ++i) {
            mfile.data()[i] = static_cast<uint8_t>(i % 256);
        }
        mfile.sync();
    }

    {
        io::MemoryMappedFile mfileRead;
        mfileRead.open(testPath, io::OpenMode::ReadOnly);
        assert(mfileRead.isMapped());
        assert(mfileRead.size() == testSize);

        for (size_t i = 0; i < testSize; ++i) {
            assert(mfileRead.data()[i] == static_cast<uint8_t>(i % 256));
        }
    }

    fs::remove(testPath);
    std::cout << "  -> PASS: MemoryMappedFile create, map, write, sync, read verified." << std::endl;
}

void testFileEncryptionRoundtrip() {
    std::cout << "[TEST 2] Testing FileProcessor Encrypt/Decrypt Roundtrip & Header Verification..." << std::endl;
    std::string originalPath = "test_plain.dat";
    std::string encryptedPath = "test_encrypted.enc";
    std::string decryptedPath = "test_decrypted.dat";
    std::string passphrase = "FAANG_Systems_Engineer_Passphrase_2026!";

    // Create 4 MB test payload
    size_t fileSize = 4 * 1024 * 1024;
    createTestFile(originalPath, fileSize, 0x3C);

    // Encrypt
    io::FileProcessor::encryptFile(originalPath, encryptedPath, passphrase);
    assert(fs::exists(encryptedPath));
    assert(fs::file_size(encryptedPath) == sizeof(crypto::EncryptedContainerHeader) + fileSize);

    // Verify Header
    auto header = io::FileProcessor::readContainerHeader(encryptedPath);
    assert(header.magic == crypto::MAGIC_HEADER);
    assert(header.plaintext_size == fileSize);

    // Decrypt
    io::FileProcessor::decryptFile(encryptedPath, decryptedPath, passphrase);
    assert(fs::exists(decryptedPath));
    assert(fs::file_size(decryptedPath) == fileSize);

    // Compare original and decrypted
    io::MemoryMappedFile origMap, decMap;
    origMap.open(originalPath, io::OpenMode::ReadOnly);
    decMap.open(decryptedPath, io::OpenMode::ReadOnly);
    assert(std::memcmp(origMap.data(), decMap.data(), fileSize) == 0);

    // Cleanup
    origMap.close();
    decMap.close();
    fs::remove(originalPath);
    fs::remove(encryptedPath);
    fs::remove(decryptedPath);

    std::cout << "  -> PASS: 4 MB File encryption/decryption roundtrip verified with bit-perfect match." << std::endl;
}

void testInPlaceAtomicTransformation() {
    std::cout << "[TEST 3] Testing In-Place Atomic File Transformation..." << std::endl;
    std::string targetPath = "test_inplace.txt";
    std::string content = "Zero-copy memory mapped I/O with AES-256-GCM AEAD container storage.";
    {
        std::ofstream ofs(targetPath);
        ofs << content;
    }

    std::string passphrase = "Secure_InPlace_Key!";
    io::FileProcessor::encryptFileInPlace(targetPath, passphrase);
    assert(fs::file_size(targetPath) == sizeof(crypto::EncryptedContainerHeader) + content.size());

    io::FileProcessor::decryptFileInPlace(targetPath, passphrase);
    assert(fs::file_size(targetPath) == content.size());

    std::ifstream ifs(targetPath);
    std::string recovered((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    assert(recovered == content);

    ifs.close();
    fs::remove(targetPath);
    std::cout << "  -> PASS: In-place atomic encryption and decryption verified." << std::endl;
}

void testTamperDetectionOnDisk() {
    std::cout << "[TEST 4] Testing Disk-Level Tamper Rejection & Safe Rollback..." << std::endl;
    std::string originalPath = "test_tamper_orig.bin";
    std::string encryptedPath = "test_tamper.enc";
    std::string decryptedPath = "test_tamper_out.bin";
    std::string passphrase = "Tamper_Verification_Key";

    createTestFile(originalPath, 64 * 1024, 0xEE);
    io::FileProcessor::encryptFile(originalPath, encryptedPath, passphrase);

    // Tamper with byte on disk
    {
        io::MemoryMappedFile encMap;
        encMap.open(encryptedPath, io::OpenMode::ReadWrite);
        encMap.data()[sizeof(crypto::EncryptedContainerHeader) + 10] ^= 0xFF; // Flip byte in ciphertext
        encMap.sync();
    }

    bool caughtAuthFail = false;
    try {
        io::FileProcessor::decryptFile(encryptedPath, decryptedPath, passphrase);
    } catch (const crypto::AuthenticationFailedException& ex) {
        caughtAuthFail = true;
    }
    assert(caughtAuthFail);
    assert(!fs::exists(decryptedPath)); // Output must be safely deleted on error

    fs::remove(originalPath);
    fs::remove(encryptedPath);
    std::cout << "  -> PASS: Tampered disk file rejected, partial decrypted output safely purged." << std::endl;
}

void benchmarkDiskIOThroughput() {
    std::cout << "[TEST 5] Disk I/O & Encryption Throughput Benchmark..." << std::endl;
    std::string inPath = "bench_in.dat";
    std::string encPath = "bench_enc.dat";
    std::string decPath = "bench_dec.dat";
    std::string passphrase = "BenchmarkPassphrase@2026";

    size_t benchSize = 32 * 1024 * 1024; // 32 MB
    createTestFile(inPath, benchSize, 0x77);

    // Benchmark Disk Encryption
    auto startEnc = std::chrono::high_resolution_clock::now();
    io::FileProcessor::encryptFile(inPath, encPath, passphrase);
    auto endEnc = std::chrono::high_resolution_clock::now();

    double encSec = std::chrono::duration<double>(endEnc - startEnc).count();
    double encMBs = (benchSize / (1024.0 * 1024.0)) / encSec;

    std::cout << "  -> Disk File Encryption: " << (benchSize / (1024 * 1024)) << " MB in " 
              << (encSec * 1000.0) << " ms (" << encMBs << " MB/s)" << std::endl;

    // Benchmark Disk Decryption
    auto startDec = std::chrono::high_resolution_clock::now();
    io::FileProcessor::decryptFile(encPath, decPath, passphrase);
    auto endDec = std::chrono::high_resolution_clock::now();

    double decSec = std::chrono::duration<double>(endDec - startDec).count();
    double decMBs = (benchSize / (1024.0 * 1024.0)) / decSec;

    std::cout << "  -> Disk File Decryption: " << (benchSize / (1024 * 1024)) << " MB in " 
              << (decSec * 1000.0) << " ms (" << decMBs << " MB/s)" << std::endl;

    fs::remove(inPath);
    fs::remove(encPath);
    fs::remove(decPath);
}

int main() {
    std::cout << "=========================================================" << std::endl;
    std::cout << "  Parallel File Encrypter: Zero-Copy I/O Test Suite      " << std::endl;
    std::cout << "=========================================================" << std::endl;

    testZeroCopyMapping();
    testFileEncryptionRoundtrip();
    testInPlaceAtomicTransformation();
    testTamperDetectionOnDisk();
    benchmarkDiskIOThroughput();

    std::cout << "\n>>> ALL ZERO-COPY I/O TESTS PASSED SUCCESSFULLY! <<<" << std::endl;
    return 0;
}
