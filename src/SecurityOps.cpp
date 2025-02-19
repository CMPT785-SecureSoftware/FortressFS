#include "SecurityOps.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <fstream>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <cstring>

namespace {

/**
 * Helper to throw runtime_error if condition is false
 */
inline void throwIf(bool condition, const char* msg) {
    if (condition) {
        throw std::runtime_error(msg);
    }
}

/**
 * Load an EVP_PKEY* from a PEM-encoded public key string (SubjectPublicKeyInfo format).
 */
EVP_PKEY* loadPublicKey(const std::string& pubKeyPem) {
    BIO* bio = BIO_new_mem_buf(pubKeyPem.data(), (int)pubKeyPem.size());
    if (!bio) throw std::runtime_error("BIO_new_mem_buf failed for public key");

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) throw std::runtime_error("PEM_read_bio_PUBKEY failed");
    return pkey;
}

/**
 * Load an EVP_PKEY* from a PEM-encoded private key string (PKCS#8 format).
 */
EVP_PKEY* loadPrivateKey(const std::string& privKeyPem) {
    BIO* bio = BIO_new_mem_buf(privKeyPem.data(), (int)privKeyPem.size());
    if (!bio) throw std::runtime_error("BIO_new_mem_buf failed for private key");

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) throw std::runtime_error("PEM_read_bio_PrivateKey failed");
    return pkey;
}

} // end anonymous namespace

namespace SecOps {

/**
 * Generate a 2048-bit RSA key pair using EVP APIs, writing keys to:
 *   <username>_private.pem (PKCS#8)
 *   <username>_public.pem  (SubjectPublicKeyInfo)
 */
bool SecurityOps::generateRSAKeyPair(const std::string& username)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        std::cerr << "EVP_PKEY_CTX_new_id failed\n";
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        std::cerr << "EVP_PKEY_keygen_init failed\n";
        return false;
    }

    // Set RSA key size = 2048 bits
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        std::cerr << "EVP_PKEY_CTX_set_rsa_keygen_bits failed\n";
        return false;
    }

    // Generate the key
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        std::cerr << "EVP_PKEY_keygen failed\n";
        return false;
    }
    EVP_PKEY_CTX_free(ctx);

    // Write the private key to <username>_private.pem (PKCS#8)
    {
        std::string privFilename = username + "_private.pem";
        BIO* bio = BIO_new_file(privFilename.c_str(), "w");
        if (!bio) {
            EVP_PKEY_free(pkey);
            std::cerr << "Failed opening private key file.\n";
            return false;
        }
        if (!PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
            BIO_free(bio);
            EVP_PKEY_free(pkey);
            std::cerr << "PEM_write_bio_PrivateKey failed\n";
            return false;
        }
        BIO_free(bio);
    }

    // Write the public key to <username>_public.pem (SubjectPublicKeyInfo)
    {
        std::string pubFilename = username + "_public.pem";
        BIO* bio = BIO_new_file(pubFilename.c_str(), "w");
        if (!bio) {
            EVP_PKEY_free(pkey);
            std::cerr << "Failed opening public key file.\n";
            return false;
        }
        if (!PEM_write_bio_PUBKEY(bio, pkey)) {
            BIO_free(bio);
            EVP_PKEY_free(pkey);
            std::cerr << "PEM_write_bio_PUBKEY failed\n";
            return false;
        }
        BIO_free(bio);
    }

    EVP_PKEY_free(pkey);
    return true;
}

/**
 * Encrypt with RSA public key using EVP_PKEY. 
 * This uses RSA_PKCS1_OAEP_PADDING by default. 
 */
std::string SecurityOps::rsaEncrypt(const std::string& data, const std::string& publicKeyPem)
{
    EVP_PKEY* pkey = loadPublicKey(publicKeyPem);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    throwIf(!ctx, "EVP_PKEY_CTX_new failed (public key context)");

    throwIf(EVP_PKEY_encrypt_init(ctx) <= 0, "EVP_PKEY_encrypt_init failed");
    throwIf(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0,
            "EVP_PKEY_CTX_set_rsa_padding failed");

    // First call: get size
    size_t outlen = 0;
    throwIf(EVP_PKEY_encrypt(ctx, nullptr, &outlen,
                             reinterpret_cast<const unsigned char*>(data.data()),
                             data.size()) <= 0, "EVP_PKEY_encrypt size failed");

    std::vector<unsigned char> outbuf(outlen);
    throwIf(EVP_PKEY_encrypt(ctx, outbuf.data(), &outlen,
                             reinterpret_cast<const unsigned char*>(data.data()),
                             data.size()) <= 0, "EVP_PKEY_encrypt failed");

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return std::string(reinterpret_cast<char*>(outbuf.data()), outlen);
}

/**
 * Decrypt with RSA private key using EVP_PKEY. 
 * Uses RSA_PKCS1_OAEP_PADDING.
 */
std::string SecurityOps::rsaDecrypt(const std::string& data, const std::string& privateKeyPem)
{
    EVP_PKEY* pkey = loadPrivateKey(privateKeyPem);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    throwIf(!ctx, "EVP_PKEY_CTX_new failed (private key context)");

    throwIf(EVP_PKEY_decrypt_init(ctx) <= 0, "EVP_PKEY_decrypt_init failed");
    throwIf(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0,
            "EVP_PKEY_CTX_set_rsa_padding failed");

    // Get size
    size_t outlen = 0;
    throwIf(EVP_PKEY_decrypt(ctx, nullptr, &outlen,
                             reinterpret_cast<const unsigned char*>(data.data()),
                             data.size()) <= 0, "EVP_PKEY_decrypt size failed");

    std::vector<unsigned char> outbuf(outlen);
    throwIf(EVP_PKEY_decrypt(ctx, outbuf.data(), &outlen,
                             reinterpret_cast<const unsigned char*>(data.data()),
                             data.size()) <= 0, "EVP_PKEY_decrypt failed");

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return std::string(reinterpret_cast<char*>(outbuf.data()), outlen);
}

//------------------ AES (unchanged) ------------------//

std::string SecurityOps::aesEncrypt(const std::string& plaintext, const std::string& key) {
    // For AES-256-CBC, we need a 256-bit key (32 bytes) and a 128-bit IV (16 bytes).
    if (key.size() != 32) {
        throw std::runtime_error("AES key must be 32 bytes for AES-256.");
    }

    // Generate random IV
    unsigned char iv[16];
    if (!RAND_bytes(iv, sizeof(iv))) {
        throw std::runtime_error("Failed to generate random IV.");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context.");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                                reinterpret_cast<const unsigned char*>(key.data()), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed.");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int outLen1 = 0;

    if (1 != EVP_EncryptUpdate(ctx,
        ciphertext.data(), &outLen1,
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        (int)plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed.");
    }

    int outLen2 = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen1, &outLen2)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed.");
    }

    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(outLen1 + outLen2);

    // Final data = IV + encrypted content
    std::string result;
    result.assign(reinterpret_cast<char*>(iv), 16); 
    result.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());

    return result;
}

std::string SecurityOps::aesDecrypt(const std::string& ciphertext, const std::string& key) {
    if (key.size() != 32) {
        throw std::runtime_error("AES key must be 32 bytes for AES-256.");
    }
    if (ciphertext.size() < 16) {
        throw std::runtime_error("Ciphertext too short (missing IV).");
    }

    // First 16 bytes = IV
    unsigned char iv[16];
    memcpy(iv, ciphertext.data(), 16);
    std::string encData = ciphertext.substr(16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context.");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
        reinterpret_cast<const unsigned char*>(key.data()), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed.");
    }

    std::vector<unsigned char> plaintext(encData.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int outLen1 = 0;

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &outLen1,
        reinterpret_cast<const unsigned char*>(encData.data()),
        (int)encData.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed.");
    }

    int outLen2 = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen1, &outLen2)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error(
            "EVP_DecryptFinal_ex failed (Possibly wrong key or corrupted data)."
        );
    }

    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(outLen1 + outLen2);
    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
}

} // namespace SecOps
