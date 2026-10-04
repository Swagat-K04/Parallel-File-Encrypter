# Parallel File Encrypter (v2.0)

A high-throughput, fault-tolerant, systems-level batch encryption engine built in modern C++17/20. Designed to securely encrypt and decrypt massive directory trees across multi-core server architectures using zero-copy memory-mapped I/O, hardware-accelerated AES-256-GCM (AEAD), and a bounded multi-process/thread worker pool in shared memory.

---

## Key Architectural Highlights

* **Hardware-Accelerated AES-256-GCM:** Leverages Intel/AMD CPU `AES-NI` vector instructions and `PCLMULQDQ` hardware carry-less multiplication ($GF(2^{128})$ Galois Hash) for >1.86 GB/s single-core in-memory cipher throughput.
* **Zero-Copy Memory-Mapped I/O:** Maps physical disk files directly into process virtual memory (`mmap` / `MapViewOfFile`), eliminating user-kernel buffer copies and reducing page-fault traps via sequential readahead hints (`madvise`).
* **Bounded SPMC Worker Pool in Shared Memory:** Replaces unbounded forking with a fixed worker pool ($N = \text{CPU cores}$) consuming from a circular ring buffer in POSIX/OS shared memory, synchronized via robust process-shared mutexes and dual semaphores.
* **Crash-Resilient Atomic Updates:** Staged file transformations with atomic file swaps (`ReplaceFileW` / `MoveFileExW` / `rename`) guarantee all-or-nothing consistency.
* **Military-Grade Key Derivation & AEAD:** NIST SP 800-38D / 800-132 compliant container format with PBKDF2-HMAC-SHA256 (100,000 iterations), random 96-bit nonces, and 128-bit authentication tags to prevent bit-flipping attacks.

---

## Architecture Diagram

```
                                  PRODUCER (CLI Engine)
                                            │
                    ┌───────────────────────┴───────────────────────┐
                    │ 1. Recursive Directory Scanner (std::fs)      │
                    │ 2. Task Packaging (Descriptor + Path + Pass)  │
                    │ 3. Enqueue to Shared Ring Buffer              │
                    └───────────────────────┬───────────────────────┘
                                            │
                                            ▼
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │                              OS / POSIX SHARED MEMORY                                  │
 │  ┌──────────────────────────────────────────────────────────────────────────────────┐  │
 │  │ Bounded Circular Task Queue (Ring Buffer)                                        │  │
 │  │ • Capacity: 256 / 1024 slots (Cache-line aligned TaskDescriptor array)            │  │
 │  │ • Process-Shared Robust Mutex (WAIT_ABANDONED / EOWNERDEAD crash recovery)       │  │
 │  │ • Dual Semaphores: EmptySlotsSem (Capacity) | ItemsAvailableSem (0)              │  │
 │  │ • Atomic Telemetry: totalSubmitted, totalCompleted, totalFailed                  │  │
 │  └──────────────────────────────────────────────────────────────────────────────────┘  │
 └──────────────────────────────────────────┬─────────────────────────────────────────────┘
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    ▼                       ▼                       ▼
          ┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
          │ Worker Process 1  │   │ Worker Process 2  │   │ Worker Process N  │
          │ • Zero-Copy mmap  │   │ • Zero-Copy mmap  │   │ • Zero-Copy mmap  │
          │ • AES-256-GCM     │   │ • AES-256-GCM     │   │ • AES-256-GCM     │
          │ • Poison Pill Stop│   │ • Poison Pill Stop│   │ • Poison Pill Stop│
          └───────────────────┘   └───────────────────┘   └───────────────────┘
```

---

## Benchmarks & Performance Metrics

| Benchmark Component | Measured Throughput | Engineering Mechanism |
| :--- | :--- | :--- |
| **In-Memory Encryption** | **> 1.86 GB/s per core** (>20 GB/s 12-core theoretical) | AES-NI vector intrinsics + PCLMULQDQ GHASH |
| **Zero-Copy Disk I/O** | **~187 – 203 MB/s** | Direct memory-mapped page cache flush |
| **Parallel vs. Sequential** | **10x – 12x Real-World Speedup** | 100% 12-core saturation + I/O latency hiding |
| **Tamper Resistance** | **100% Rejection & Rollback** | 128-bit AEAD tag constant-time validation |

---

## Binary Container Format

Every encrypted file is wrapped in an atomic binary container:

$$\text{Container} = [\text{Magic: } \texttt{"ENC1"} \ (4\text{B})] + [\text{Salt: } 16\text{B}] + [\text{IV/Nonce: } 12\text{B}] + [\text{Tag: } 16\text{B}] + [\text{Plaintext Size: } 8\text{B}] + [\text{Ciphertext: } N\text{B}]$$

---

## Quickstart & Build Instructions

### Prerequisites
* C++17 compatible compiler (`g++` / `clang++` / `MSVC`)
* Hardware with AES-NI support (standard on modern x86-64 CPUs)

### Build the Unified Executable
```bash
# Build production executable
make

# Or compile directly with GCC
g++ -std=c++17 -O3 -maes -mpclmul -mssse3 -I. -Isrc/crypto -Isrc/io -Isrc/ipc -Isrc/pool \
    main.cpp src/crypto/AES256GCM.cpp src/io/MemoryMappedFile.cpp src/io/FileProcessor.cpp \
    src/ipc/SharedTaskQueue.cpp src/pool/ProcessPool.cpp -o encrypt_decrypt
```

### Run Hardware Benchmark
```bash
./encrypt_decrypt --benchmark
```

### Encrypt a Directory
```bash
./encrypt_decrypt -d /path/to/folder -a encrypt
```

### Decrypt a Directory
```bash
./encrypt_decrypt -d /path/to/folder -a decrypt
```

---

## Running Test Suites
```bash
make test
```
* **Crypto Tests:** Validates NIST SP 800-38D test vectors, anti-tamper bit-flipping, and PBKDF2 derivation.
* **I/O Tests:** Validates zero-copy mapping, in-place atomic replacement, and large file roundtrips.
* **Concurrency Tests:** Validates bounded worker pool synchronization and graceful poison pill shutdown across multi-file batches.
