CXX = g++
CXXFLAGS = -std=c++17 -O3 -Wall -Wextra -maes -mpclmul -mssse3 -MMD -MP -I. -Isrc/crypto -Isrc/io -Isrc/ipc -Isrc/pool

TARGET = encrypt_decrypt

SRC = main.cpp \
      src/crypto/AES256GCM.cpp \
      src/io/MemoryMappedFile.cpp \
      src/io/FileProcessor.cpp \
      src/ipc/SharedTaskQueue.cpp \
      src/pool/ProcessPool.cpp

OBJ = $(SRC:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	@echo "Linking $@..."
	$(CXX) $(CXXFLAGS) $^ -o $@

%.o: %.cpp
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) -c $< -o $@

test: all
	@echo "Running all test suites..."
	$(CXX) $(CXXFLAGS) src/crypto/AES256GCM.cpp tests/test_crypto.cpp -o tests/test_crypto.exe
	./tests/test_crypto.exe
	$(CXX) $(CXXFLAGS) src/crypto/AES256GCM.cpp src/io/MemoryMappedFile.cpp src/io/FileProcessor.cpp tests/test_io.cpp -o tests/test_io.exe
	./tests/test_io.exe
	$(CXX) $(CXXFLAGS) src/crypto/AES256GCM.cpp src/io/MemoryMappedFile.cpp src/io/FileProcessor.cpp src/ipc/SharedTaskQueue.cpp src/pool/ProcessPool.cpp tests/test_pool.cpp -o tests/test_pool.exe
	./tests/test_pool.exe

clean:
	@echo "Cleaning up..."
	rm -f $(OBJ) $(TARGET) $(TARGET).exe tests/*.exe tests/*.d src/*/*.o src/*/*.d *.d

.PHONY: clean all test

-include $(OBJ:.o=.d)
