#ifndef SECURITY_OPS_H
#define SECURITY_OPS_H

#include <string>

namespace SecOps {

    /**
     * SecurityOps provides cryptographic functions:
     * - RSA key pair generation and RSA encryption/decryption (OAEP padding).
     * - AES-256-CBC encryption/decryption.
     * - SHA-256 hashing.
     */
    class SecurityOps {
    public:
        // Generate a 2048-bit RSA key pair and write keys to files:
        // "<username>_private.pem" and "<username>_public.pem".
        static bool generateRSAKeyPair(const std::string &username);

        // RSA encryption and decryption.
        static std::string rsaEncrypt(const std::string &plaintext, const std::string &publicKeyPem);
        static std::string rsaDecrypt(const std::string &ciphertext, const std::string &privateKeyPem);

        // AES-256-CBC encryption and decryption.
        // Key must be exactly 32 bytes.
        static std::string aesEncrypt(const std::string &plaintext, const std::string &key);
        static std::string aesDecrypt(const std::string &ciphertext, const std::string &key);

        // Compute SHA-256 hash and return it as a hex string.
        static std::string sha256(const std::string &data);
    };
}

#endif