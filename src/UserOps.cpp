#include "UserOps.h"
#include "SecurityOps.h"
#include "FileOps.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>

namespace UOps {

std::unordered_map<std::string, User> UserOps::users;

static const std::string FILESYSTEM_DIR = "filesystem";
static const std::string ENCRYPTED_KEYS_DIR = FILESYSTEM_DIR + "/EncryptedKeys";
// Public keys folder (outside the filesystem)
static const std::string PUBLIC_KEYS_DIR = "public_keys";
// Fixed symmetric key for encrypting user keyfiles.
static const std::string ADMIN_SYMMETRIC_KEY = "0123456789abcdef0123456789abcdef";

bool UserOps::createUser(const std::string &username) {
    if (userExists(username)) {
        std::cout << "User " << username << " already exists\n";
        return false;
    }
    // Generate RSA key pair for the new user.
    if (!SecOps::SecurityOps::generateRSAKeyPair(username)) {
        std::cout << "Failed to generate key pair for " << username << "\n";
        return false;
    }
    // Read the user's private key.
    std::ifstream privFile(username + "_private.pem");
    std::stringstream privBuf;
    privBuf << privFile.rdbuf();
    std::string userPriv = privBuf.str();

    // Read the user's public key.
    std::ifstream pubFile(username + "_public.pem");
    std::stringstream pubBuf;
    pubBuf << pubFile.rdbuf();
    std::string userPub = pubBuf.str();

    // Encrypt the user's private key using the admin's symmetric key.
    std::string encryptedUserKey = SecOps::SecurityOps::aesEncrypt(userPriv, ADMIN_SYMMETRIC_KEY);

    // Store the encrypted key in EncryptedKeys as <username>_keyfile.
    std::string keyfilePath = ENCRYPTED_KEYS_DIR + "/" + username + "_keyfile";
    if (!Ops::FileOps::writeFile(keyfilePath, encryptedUserKey)) {
        std::cout << "Failed to write user keyfile\n";
        return false;
    }
    // Create the user's folder structure in the filesystem.
    std::string userDir = FILESYSTEM_DIR + "/" + username;
    Ops::FileOps::makeDirectory(userDir + "/personal");
    Ops::FileOps::makeDirectory(userDir + "/shared");

    // Move the public key to the dedicated public_keys folder.
    std::string pubDest = PUBLIC_KEYS_DIR + "/" + username + "_public.pem";
    std::filesystem::rename(username + "_public.pem", pubDest);

    // Add the new user to the in-memory user table.
    users[username] = User{username, userPriv, userPub, false};

    std::cout << "Created user: " << username << "\n";
    return true;
}

bool UserOps::userExists(const std::string &username) {
    return (users.find(username) != users.end());
}

User UserOps::getUser(const std::string &username) {
    if (userExists(username)) {
        return users[username];
    }
    return User{"", "", "", false};
}

// The login function attempts to log in by reading an encrypted keyfile.
// It decrypts the keyfile using the admin symmetric key (ADMIN_SYMMETRIC_KEY).
// If the decrypted key equals "ADMIN_PRIV", the admin is logged in;
// otherwise, the username is extracted from the keyfile name (assumed to be in the form "<username>_keyfile").
std::string UserOps::login(const std::string &keyfilePath) {
    std::string keyData;
    // First, try reading the file from the given path.
    std::ifstream ifs(keyfilePath, std::ios::binary);
    if (!ifs) {
        // If not found, try looking under ENCRYPTED_KEYS_DIR.
        std::string alt = std::string("filesystem/EncryptedKeys/") + "/" + keyfilePath;
        std::ifstream ifs2(alt, std::ios::binary);
        if (!ifs2)
            return "";
        keyData = std::string((std::istreambuf_iterator<char>(ifs2)),
                              std::istreambuf_iterator<char>());
    } else {
        keyData = std::string((std::istreambuf_iterator<char>(ifs)),
                              std::istreambuf_iterator<char>());
    }
    if (keyData.empty())
        return "";
    
    // Decrypt the key using AES. (The keyfile is expected to be encrypted.)
    std::string decrypted;
    try {
        decrypted = SecOps::SecurityOps::aesDecrypt(keyData, ADMIN_SYMMETRIC_KEY);
    } catch (...) {
        return "";
    }
    
    // If the decrypted key equals "ADMIN_PRIV", log in as admin.
    if (decrypted == "ADMIN_PRIV") {
        if (users.find("admin") == users.end())
            users["admin"] = User{"admin", decrypted, "", true};
        return "admin";
    }
    
    // Otherwise, assume the keyfile is named in the format "<username>_keyfile"
    // and extract the username.
    size_t pos = keyfilePath.find("_keyfile");
    if (pos != std::string::npos) {
        std::string uname = keyfilePath.substr(0, pos);
        if (users.find(uname) == users.end()) {
            // Load the public key from the public_keys folder.
            std::ifstream pub((PUBLIC_KEYS_DIR + "/" + uname + "_public.pem").c_str());
            std::stringstream pubBuf;
            pubBuf << pub.rdbuf();
            std::string userPub = pubBuf.str();
            users[uname] = User{uname, decrypted, userPub, false};
        }
        return uname;
    }
    return "";
}

} // namespace UOps