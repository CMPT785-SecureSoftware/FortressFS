#ifndef SECURITY_OPS_H
#define SECURITY_OPS_H

#include <string>

namespace SecOps 
{
    // Contains RSA and AES utilities, now using EVP APIs for RSA
    class SecurityOps {
    public:
        // Generate a 2048-bit RSA key pair, stored in <username>_private.pem and <username>_public.pem
        static bool generateRSAKeyPair(const std::string& username);

        // Optional: RSA encryption/decryption using modern EVP APIs
        // (Not used by default in this project, but available if needed.)
        static std::string rsaEncrypt(const std::string& data, const std::string& publicKeyPem);
        static std::string rsaDecrypt(const std::string& data, const std::string& privateKeyPem);

        // AES encryption/decryption, unchanged
        // key must be 32 bytes for AES-256
        static std::string aesEncrypt(const std::string& plaintext, const std::string& key);
        static std::string aesDecrypt(const std::string& ciphertext, const std::string& key);
    };
}

#endif
