#include "UserOps.h"
#include "SecurityOps.h"
#include "FileOps.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace UOps {

    // In-memory cache of users.
    std::unordered_map<std::string, User> UserOps::users;
    static const std::string PRIVATE_KEYS_DIR = "private_keys";
    static const std::string PUBLIC_KEYS_DIR = "public_keys";

    /**
     * createUser:
     * - Validates the username.
     * - Generates RSA key pairs.
     * - Moves keyfiles to proper directories.
     * - Creates the per-user mapping file (named as sha256("<username>_file_mapping.json"))
     *   in the user's root folder (which is hashed).
     * - Updates the global mapping.
     */
    bool UserOps::createUser(const std::string &username) {
        for (char c : username) {
            if (!std::isalnum(c) && c != '-') {
                std::cerr << "Invalid username. Only alphanumeric characters and hyphen are allowed.\n";
                return false;
            }
        }
        if (!SecOps::SecurityOps::generateRSAKeyPair(username)) {
            std::cout << "Failed to generate key pair for " << username << "\n";
            return false;
        }
        std::ifstream privFile(username + "_private.pem");
        std::stringstream privBuf;
        privBuf << privFile.rdbuf();
        std::string userPriv = privBuf.str();

        std::ifstream pubFile(username + "_public.pem");
        std::stringstream pubBuf;
        pubBuf << pubFile.rdbuf();
        std::string userPub = pubBuf.str();

        std::filesystem::create_directories(PRIVATE_KEYS_DIR);
        std::string keyfilePath = PRIVATE_KEYS_DIR + "/" + username + "_keyfile.pem";
        if (!Ops::FileOps::writeFile(keyfilePath, userPriv)) {
            std::cout << "Failed to write user keyfile\n";
            return false;
        }
        std::filesystem::create_directories(PUBLIC_KEYS_DIR);
        std::string pubDest = PUBLIC_KEYS_DIR + "/" + username + "_public.pem";
        std::filesystem::rename(username + "_public.pem", pubDest);

        users[username] = User{username, userPriv, userPub, false};
        std::cout << "Created user: " << username << "\n";
        std::filesystem::remove(username + "_public.pem");

        // Create per-user mapping file.
        std::string userRootDir = "filesystem/" + SecOps::SecurityOps::sha256(username);
        std::filesystem::create_directories(userRootDir);
        json userMapping;
        userMapping["username"] = username;
        // Files will be stored as: { <hash>: [original name, "d" or "f"] }.
        userMapping["files"] = json::object();
        std::string mappingStr = userMapping.dump(4);
        std::string encryptedMapping = SecOps::SecurityOps::rsaEncrypt(mappingStr, userPub);
        std::string mappingFileName = SecOps::SecurityOps::sha256(username + "_file_mapping.json");
        std::string mappingFilePath = userRootDir + "/" + mappingFileName;
        Ops::FileOps::writeFile(mappingFilePath, encryptedMapping);

        // Update global mapping.
        if (!UserOps::mapUser(username, userPub)) {
            std::cout << "Failed to update global mapping for " << username << "\n";
            return false;
        }
        return true;
    }

    // getUser returns the user from the in-memory cache.
    User UserOps::getUser(const std::string &username) {
        if (users.find(username) != users.end())
            return users[username];
        return User{"", "", "", false};
    }

    // userExists returns true if the user is already in the in-memory cache.
    bool UserOps::userExists(const std::string &username) {
        return (users.find(username) != users.end());
    }

    /**
     * login:
     * - Reads the provided keyfile to obtain the private key.
     * - Extracts the username from the keyfile's name.
     * - Scans the user's hashed root directory for the single mapping file.
     * - Decrypts the mapping file using the provided private key and verifies that it contains the correct username.
     * - Loads the user's public key from disk and caches the user.
     */
    std::string UserOps::login(const std::string &keyfilePath) {
        std::filesystem::path p(keyfilePath);
        std::string baseKeyfile = p.filename().string();

        std::string keyData;
        std::ifstream ifs(keyfilePath, std::ios::binary);
        if (!ifs) {
            std::string alt = PRIVATE_KEYS_DIR + "/" + baseKeyfile;
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
        size_t pos = baseKeyfile.find("_keyfile.pem");
        if (pos == std::string::npos)
            return "";
        std::string uname = baseKeyfile.substr(0, pos);

        // Locate the per-user mapping file by scanning the user's root directory.
        std::string userRootDir = "filesystem/" + SecOps::SecurityOps::sha256(uname);
        if (!std::filesystem::exists(userRootDir)) {
            std::cerr << "User root directory not found for " << uname << "\n";
            return "";
        }
        std::string mappingFilePath = "";
        for (const auto &entry : std::filesystem::directory_iterator(userRootDir)) {
            if (!entry.is_directory()) {
                mappingFilePath = entry.path().string();
                break;
            }
        }
        if (mappingFilePath.empty()) {
            std::cerr << "Mapping file not found for user " << uname << "\n";
            return "";
        }
        std::string encryptedMapping = Ops::FileOps::readFile(mappingFilePath);
        std::string decryptedMapping;
        try {
            decryptedMapping = SecOps::SecurityOps::rsaDecrypt(encryptedMapping, keyData);
        } catch (std::exception &e) {
            std::cerr << "User mapping decryption failed: " << e.what() << "\n";
            return "";
        }
        json mapping;
        try {
            mapping = json::parse(decryptedMapping);
        } catch (...) {
            std::cerr << "Failed to parse user mapping JSON\n";
            return "";
        }
        if (!mapping.contains("username") || mapping["username"] != uname) {
            std::cerr << "User mapping does not match for " << uname << "\n";
            return "";
        }
        // Load user's public key.
        std::string pubFilePath = PUBLIC_KEYS_DIR + "/" + uname + "_public.pem";
        std::ifstream pubFile(pubFilePath);
        std::stringstream pubBuf;
        pubBuf << pubFile.rdbuf();
        std::string userPub = pubBuf.str();
        users[uname] = User{uname, keyData, userPub, false};
        return uname;
    }

    /**
     * mapUser:
     * Updates global_mapping.json with the user's base directory information:
     * - "root": hash(username)
     * - "shared": hash("shared")
     * - "shared_files": an empty object to store files shared to the user.
     */
    bool UserOps::mapUser(const std::string &username, const std::string &publicKey) {
        json mapping;
        std::ifstream ifs("global_mapping.json");
        if (ifs) {
            ifs >> mapping;
            ifs.close();
        }
        mapping[username] = {
            { "root", SecOps::SecurityOps::sha256(username) },
            { "shared", SecOps::SecurityOps::sha256("shared") },
            { "shared_files", json::object() }
        };
        std::ofstream ofs("global_mapping.json");
        ofs << mapping.dump(4);
        return ofs.good();
    }

    /**
     * updateAdminMapping:
     * Updates admin_mapping.json (stored at the filesystem root) with a new user's info.
     * The admin_mapping file (filename = sha256("admin_mapping.json")) maps usernames to their private keys.
     * This file is encrypted using AES with a key derived from admin's private key.
     */
    bool UserOps::updateAdminMapping(const std::string &username, const std::string &userPrivateKey, const std::string &adminPrivateKey) {
        std::string adminMappingFileName = SecOps::SecurityOps::sha256("admin_mapping.json");
        std::string adminMappingPath = "filesystem/" + adminMappingFileName;
        json adminMapping;
        if (std::filesystem::exists(adminMappingPath)) {
            std::string encrypted = Ops::FileOps::readFile(adminMappingPath);
            std::string key = adminPrivateKey.substr(0, 32);
            try {
                std::string decrypted = SecOps::SecurityOps::aesDecrypt(encrypted, key);
                adminMapping = json::parse(decrypted);
            } catch (...) {
                adminMapping = json::object();
            }
        }
        adminMapping[username] = userPrivateKey;
        std::string plain = adminMapping.dump(4);
        std::string key = adminPrivateKey.substr(0, 32);
        std::string encrypted = SecOps::SecurityOps::aesEncrypt(plain, key);
        return Ops::FileOps::writeFile(adminMappingPath, encrypted);
    }
}