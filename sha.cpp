#include <iostream>
#include <iomanip>
#include <openssl/evp.h>
#include <fstream>
void computeFileSHA256(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Unable to open file: " << filePath << std::endl;
        return;
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "Failed to create digest context." << std::endl;
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        std::cerr << "Failed to initialize digest context." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return;
    }

    const size_t bufferSize = 8192;
    char buffer[bufferSize];

    while (file.read(buffer, bufferSize) || file.gcount() > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1) {
            std::cerr << "Failed to update hash." << std::endl;
            EVP_MD_CTX_free(mdctx);
            return;
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLength = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &hashLength) != 1) {
        std::cerr << "Failed to finalize hash." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);

    std::cout << "SHA-256 hash: ";
    for (unsigned int i = 0; i < hashLength; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    std::cout << std::endl;
}
void computeFileSHA384(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Unable to open file: " << filePath << std::endl;
        return;
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "Failed to create digest context." << std::endl;
        return;
    }

    // Use SHA-384 algorithm
    if (EVP_DigestInit_ex(mdctx, EVP_sha384(), nullptr) != 1) {
        std::cerr << "Failed to initialize digest context with SHA-384." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return;
    }

    const size_t bufferSize = 8192;
    char buffer[bufferSize];

    while (file.read(buffer, bufferSize) || file.gcount() > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1) {
            std::cerr << "Failed to update hash." << std::endl;
            EVP_MD_CTX_free(mdctx);
            return;
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLength = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &hashLength) != 1) {
        std::cerr << "Failed to finalize hash." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);

    // Output SHA-384 hash
    std::cout << "SHA-384 hash: ";
    for (unsigned int i = 0; i < hashLength; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    std::cout << std::endl;
}
void computeFileSHA512(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Unable to open file: " << filePath << std::endl;
        return;
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "Failed to create digest context." << std::endl;
        return;
    }

    // Use SHA-512 algorithm
    if (EVP_DigestInit_ex(mdctx, EVP_sha512(), nullptr) != 1) {
        std::cerr << "Failed to initialize digest context with SHA-384." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return;
    }

    const size_t bufferSize = 8192;
    char buffer[bufferSize];

    while (file.read(buffer, bufferSize) || file.gcount() > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1) {
            std::cerr << "Failed to update hash." << std::endl;
            EVP_MD_CTX_free(mdctx);
            return;
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLength = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &hashLength) != 1) {
        std::cerr << "Failed to finalize hash." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);

    // Output SHA-512 hash
    std::cout << "SHA-512 hash: ";
    for (unsigned int i = 0; i < hashLength; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    std::cout << std::endl;
}
void computeFileKeccak256(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Unable to open file: " << filePath << std::endl;
        return;
    }

    // Tworzenie kontekstu dla hashowania
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "Failed to create digest context." << std::endl;
        return;
    }

    // Inicjalizacja kontekstu z algorytmem Keccak256 (SHA3-256)
    if (EVP_DigestInit_ex(mdctx, EVP_sha3_256(), nullptr) != 1) {
        std::cerr << "Failed to initialize digest context." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return;
    }

    const size_t bufferSize = 8192;
    char buffer[bufferSize];

    // Aktualizacja hashu danymi z pliku
    while (file.read(buffer, bufferSize) || file.gcount() > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1) {
            std::cerr << "Failed to update hash." << std::endl;
            EVP_MD_CTX_free(mdctx);
            return;
        }
    }

    // Finalizacja hashowania
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLength = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &hashLength) != 1) {
        std::cerr << "Failed to finalize hash." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);

    // Wyświetlanie wyniku w formacie szesnastkowym
    std::cout << "Keccak256 (SHA3-256) hash: ";
    for (unsigned int i = 0; i < hashLength; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    std::cout << std::endl;
}