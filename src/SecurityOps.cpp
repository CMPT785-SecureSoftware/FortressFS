#include "SecurityOps.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstring>
#include <iomanip>

namespace {
    // Retrieves the latest OpenSSL error as a string.
    std::string getOpenSSLError() {
        unsigned long errCode = ERR_get_error();
        char buf[256];
        ERR_error_string_n(errCode, buf, sizeof(buf));
        return std::string(buf);
    }

    // Loads a public key from a PEM string.
    EVP_PKEY* loadPublicKey(const std::string &pubKeyPem) {
        BIO* bio = BIO_new_mem_buf(pubKeyPem.data(), static_cast<int>(pubKeyPem.size()));
        if (!bio)
            throw std::runtime_error("BIO_new_mem_buf failed for public key: " + getOpenSSLError());
        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey)
            throw std::runtime_error("PEM_read_bio_PUBKEY failed: " + getOpenSSLError());
        return pkey;
    }

    // Loads a private key from a PEM string.
    EVP_PKEY* loadPrivateKey(const std::string &privKeyPem) {
        BIO* bio = BIO_new_mem_buf(privKeyPem.data(), static_cast<int>(privKeyPem.size()));
        if (!bio)
            throw std::runtime_error("BIO_new_mem_buf failed for private key: " + getOpenSSLError());
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey)
            throw std::runtime_error("PEM_read_bio_PrivateKey failed: " + getOpenSSLError());
        return pkey;
    }
}

namespace SecOps {

bool SecurityOps::generateRSAKeyPair(const std::string &username)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        std::cerr << "EVP_PKEY_CTX_new_id failed: " << getOpenSSLError() << "\n";
        return false;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "EVP_PKEY_keygen_init failed: " << getOpenSSLError() << "\n";
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << "EVP_PKEY_CTX_set_rsa_keygen_bits failed: " << getOpenSSLError() << "\n";
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "EVP_PKEY_keygen failed: " << getOpenSSLError() << "\n";
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY_CTX_free(ctx);

    // Write private key to file.
    {
        std::string privFilename = username + "_keyfile.pem";
        BIO* bio = BIO_new_file(privFilename.c_str(), "w");
        if (!bio) {
            EVP_PKEY_free(pkey);
            std::cerr << "Failed opening private key file for writing: " << getOpenSSLError() << "\n";
            return false;
        }
        if (!PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
            std::string err = getOpenSSLError();
            BIO_free(bio);
            EVP_PKEY_free(pkey);
            std::cerr << "PEM_write_bio_PrivateKey failed: " << err << "\n";
            return false;
        }
        BIO_free(bio);
    }

    // Write public key to file.
    {
        std::string pubFilename = username + "_public.pem";
        BIO* bio = BIO_new_file(pubFilename.c_str(), "w");
        if (!bio) {
            EVP_PKEY_free(pkey);
            std::cerr << "Failed opening public key file for writing: " << getOpenSSLError() << "\n";
            return false;
        }
        if (!PEM_write_bio_PUBKEY(bio, pkey)) {
            std::string err = getOpenSSLError();
            BIO_free(bio);
            EVP_PKEY_free(pkey);
            std::cerr << "PEM_write_bio_PUBKEY failed: " << err << "\n";
            return false;
        }
        BIO_free(bio);
    }
    EVP_PKEY_free(pkey);
    return true;
}

std::string SecurityOps::rsaEncrypt(const std::string &data, const std::string &publicKeyPem)
{
    EVP_PKEY* pkey = loadPublicKey(publicKeyPem);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_CTX_new failed (public key context): " + getOpenSSLError());
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_encrypt_init failed: " + getOpenSSLError());
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_CTX_set_rsa_padding failed: " + getOpenSSLError());
    }
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen,
                         reinterpret_cast<const unsigned char*>(data.data()),
                         data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_encrypt size determination failed: " + getOpenSSLError());
    }
    std::vector<unsigned char> outbuf(outlen);
    if (EVP_PKEY_encrypt(ctx, outbuf.data(), &outlen,
                         reinterpret_cast<const unsigned char*>(data.data()),
                         data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_encrypt failed: " + getOpenSSLError());
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return std::string(reinterpret_cast<char*>(outbuf.data()), outlen);
}

std::string SecurityOps::rsaDecrypt(const std::string &data, const std::string &privateKeyPem)
{
    EVP_PKEY* pkey = loadPrivateKey(privateKeyPem);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_CTX_new failed (private key context): " + getOpenSSLError());
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_decrypt_init failed: " + getOpenSSLError());
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_CTX_set_rsa_padding failed: " + getOpenSSLError());
    }
    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen,
                         reinterpret_cast<const unsigned char*>(data.data()),
                         data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_decrypt size determination failed: " + getOpenSSLError());
    }
    std::vector<unsigned char> outbuf(outlen);
    if (EVP_PKEY_decrypt(ctx, outbuf.data(), &outlen,
                         reinterpret_cast<const unsigned char*>(data.data()),
                         data.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_decrypt failed: " + getOpenSSLError());
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return std::string(reinterpret_cast<char*>(outbuf.data()), outlen);
}

std::string SecurityOps::aesEncrypt(const std::string &plaintext, const std::string &key) {
    if (key.size() != 32)
        throw std::runtime_error("AES key must be 32 bytes for AES-256. " + getOpenSSLError());

    unsigned char iv[16];
    if (!RAND_bytes(iv, sizeof(iv)))
        throw std::runtime_error("Failed to generate IV: " + getOpenSSLError());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLError());

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const unsigned char*>(key.data()), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed: " + getOpenSSLError());
    }
    // Explicitly enable PKCS#7 padding.
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int outLen1 = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen1,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed: " + getOpenSSLError());
    }
    int outLen2 = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen1, &outLen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed: " + getOpenSSLError());
    }
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(outLen1 + outLen2);

    // Prepend the IV to the ciphertext.
    std::string result;
    result.assign(reinterpret_cast<char*>(iv), 16);
    result.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
    return result;
}

std::string SecurityOps::aesDecrypt(const std::string &ciphertext, const std::string &key) {
    if (key.size() != 32)
        throw std::runtime_error("AES key must be 32 bytes for AES-256. " + getOpenSSLError());
    if (ciphertext.size() < 16)
        throw std::runtime_error("Ciphertext too short (missing IV). " + getOpenSSLError());

    unsigned char iv[16];
    memcpy(iv, ciphertext.data(), 16);
    std::string encData = ciphertext.substr(16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("Failed to create cipher context: " + getOpenSSLError());

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const unsigned char*>(key.data()), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed: " + getOpenSSLError());
    }
    // Explicitly enable padding.
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    
    std::vector<unsigned char> plaintext(encData.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int outLen1 = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outLen1,
                          reinterpret_cast<const unsigned char*>(encData.data()),
                          encData.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed: " + getOpenSSLError());
    }
    int outLen2 = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen1, &outLen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed (wrong key or corrupted data): " + getOpenSSLError());
    }
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(outLen1 + outLen2);
    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
}

std::string SecurityOps::sha256(const std::string &data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

/**
 * hybridEncrypt:
 * Implements hybrid encryption:
 * 1. Generate a random 32-byte AES key.
 * 2. Encrypt the plaintext using AES-256-CBC.
 * 3. Encrypt the AES key using RSA with the provided public key.
 * 4. Return the concatenation: [RSA-encrypted AES key (256 bytes)] || [AES ciphertext].
 */
std::string SecurityOps::hybridEncrypt(const std::string &plaintext, const std::string &publicKeyPem) {
    // Generate random 32-byte AES key.
    unsigned char aesKey[32];
    if (!RAND_bytes(aesKey, sizeof(aesKey)))
        throw std::runtime_error("Failed to generate AES key: " + getOpenSSLError());
    std::string aesKeyStr(reinterpret_cast<char*>(aesKey), 32);

    // Encrypt the plaintext using AES.
    std::string aesCiphertext = aesEncrypt(plaintext, aesKeyStr);

    // Encrypt the AES key using RSA with the public key.
    std::string encAesKey = rsaEncrypt(aesKeyStr, publicKeyPem);
    // For a 2048-bit RSA key, encAesKey should be 256 bytes.

    // Concatenate the RSA-encrypted AES key and the AES ciphertext.
    return encAesKey + aesCiphertext;
}

/**
 * hybridDecrypt:
 * Implements hybrid decryption:
 * 1. Extracts the first 256 bytes (RSA-encrypted AES key) and decrypts it using RSA (with the private key).
 * 2. Uses the recovered AES key to decrypt the remaining ciphertext (which includes the IV).
 */
std::string SecurityOps::hybridDecrypt(const std::string &ciphertext, const std::string &privateKeyPem) {
    // For a 2048-bit RSA key, the RSA-encrypted AES key is 256 bytes.
    if (ciphertext.size() < 256)
        throw std::runtime_error("Ciphertext too short for hybrid decryption.");

    std::string encAesKey = ciphertext.substr(0, 256);
    std::string aesCiphertext = ciphertext.substr(256);

    // RSA-decrypt the AES key.
    std::string aesKeyStr = rsaDecrypt(encAesKey, privateKeyPem);
    if (aesKeyStr.size() != 32)
        throw std::runtime_error("Recovered AES key size is incorrect.");

    // Decrypt the AES ciphertext.
    return aesDecrypt(aesCiphertext, aesKeyStr);
}

} // namespace SecOps