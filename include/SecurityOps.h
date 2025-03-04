#ifndef SECURITY_OPS_H
#define SECURITY_OPS_H

#include <string>

namespace SecOps {

    /**
     * SecurityOps provides cryptographic functions:
     * - RSA key pair generation, RSA encryption and decryption (using OAEP padding).
     * - AES-256-CBC encryption and decryption.
     * - SHA-256 hashing.
     */
    class SecurityOps {
    public:
        // Generates a 2048-bit RSA key pair and writes keys to files:
        // "<username>_private.pem" and "<username>_public.pem".
        static bool generateRSAKeyPair(const std::string &username);

        // Encrypts plaintext using RSA and the given public key (PEM format).
        static std::string rsaEncrypt(const std::string &plaintext, const std::string &publicKeyPem);

        // Decrypts ciphertext using RSA and the given private key (PEM format).
        static std::string rsaDecrypt(const std::string &ciphertext, const std::string &privateKeyPem);

        // Encrypts plaintext using AES-256-CBC with the provided 32-byte key.
        static std::string aesEncrypt(const std::string &plaintext, const std::string &key);

        // Decrypts ciphertext using AES-256-CBC with the provided 32-byte key.
        static std::string aesDecrypt(const std::string &ciphertext, const std::string &key);

        // Computes the SHA-256 hash of the input data and returns it as a hexadecimal string.
        static std::string sha256(const std::string &data);
    };
}

#endif