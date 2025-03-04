#ifndef SECURITY_OPS_H
#define SECURITY_OPS_H

#include <string>

namespace SecOps {

    /**
     * SecurityOps provides cryptographic functions including RSA key-pair
     * generation, RSA and AES encryption/decryption, and SHA-256 hashing.
     */
    class SecurityOps {
    public:
        // Generate a 2048-bit RSA key pair and write the keys to files:
        // "<username>_private.pem" and "<username>_public.pem".
        static bool generateRSAKeyPair(const std::string &username);

        // RSA encryption/decryption using EVP APIs with OAEP padding.
        // The RSA functions operate on raw strings.
        static std::string rsaEncrypt(const std::string &plaintext, const std::string &publicKeyPem);
        static std::string rsaDecrypt(const std::string &ciphertext, const std::string &privateKeyPem);

        // AES-256-CBC encryption/decryption.
        // The key must be exactly 32 bytes.
        static std::string aesEncrypt(const std::string &plaintext, const std::string &key);
        static std::string aesDecrypt(const std::string &ciphertext, const std::string &key);

        // Compute the SHA-256 hash of input data and return the result as a hex string.
        static std::string sha256(const std::string &data);
    };
}

#endif