#ifndef SECURITY_OPS_H
#define SECURITY_OPS_H

#include <string>

namespace SecOps {

    class SecurityOps {
    public:
        // Generate a 2048-bit RSA key pair (using EVP) and write:
        //   <username>_private.pem and <username>_public.pem.
        // These files will later be stored (encrypted) in the EncryptedKeys folder.
        static bool generateRSAKeyPair(const std::string &username);

        // RSA encryption/decryption using EVP APIs (using OAEP padding)
        static std::string rsaEncrypt(const std::string &plaintext, const std::string &publicKeyPem);
        static std::string rsaDecrypt(const std::string &ciphertext, const std::string &privateKeyPem);

        // AES-256-CBC encryption/decryption.
        // The key must be exactly 32 bytes for AES-256.
        static std::string aesEncrypt(const std::string &plaintext, const std::string &key);
        static std::string aesDecrypt(const std::string &ciphertext, const std::string &key);
    };
}

#endif