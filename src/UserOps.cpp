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

    // In-memory cache for users.
    std::unordered_map<std::string, User> UserOps::users;
    static const std::string PRIVATE_KEYS_DIR = "private_keys";
    static const std::string PUBLIC_KEYS_DIR = "public_keys";

    /**
     * createUser:
     * - Validates the username.
     * - Generates RSA key pairs and moves key files to appropriate directories.
     * - Creates the per-user mapping file (named as the SHA-256 hash of "<username>_file_mapping.json")
     *   in the user's hashed root directory.
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
        std::ifstream privFile(username + "_keyfile.pem");
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
        // Create hashed "personal" and "shared" directories under userRootDir.
        std::string personalDir = userRootDir + "/" + SecOps::SecurityOps::sha256("personal");
        std::string sharedDir   = userRootDir + "/" + SecOps::SecurityOps::sha256("shared");
        std::filesystem::create_directories(personalDir);
        std::filesystem::create_directories(sharedDir);

        json userMapping;
        userMapping["username"] = username;
        // Files and directories are stored as { hash : [originalName, type] }.
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

    /**
     * getUser:
     * Returns the user from the in-memory cache.
     */
    User UserOps::getUser(const std::string &username) {
        if (users.find(username) != users.end())
            return users[username];
        return User{"", "", "", false};
    }

    /**
     * userExists:
     * Checks whether the user is present in the in-memory cache.
     */
    bool UserOps::userExists(const std::string &username) {
        return (users.find(username) != users.end());
    }

    /**
     * login:
     * - Reads the keyfile to obtain the private key.
     * - Extracts the username from the keyfile's name.
     * - Scans the user's hashed root directory for the mapping file.
     * - Decrypts the mapping file with the provided private key and verifies the username.
     * - Loads the user's public key from disk and caches the user.
     */
    std::string UserOps::login(const std::string &keyfilePath) {
        // Attempt to read the keyfile content from the given path.
        std::ifstream ifs(keyfilePath, std::ios::binary);
        if (!ifs) {
            std::cerr << "Unable to open keyfile: " << keyfilePath << "\n";
            return "";
        }
        std::string keyData((std::istreambuf_iterator<char>(ifs)),
                            std::istreambuf_iterator<char>());
        ifs.close();
        if (keyData.empty()) {
            std::cerr << "Keyfile is empty: " << keyfilePath << "\n";
            return "";
        }
    
        // Extract the filename (last component of the path).
        std::filesystem::path p(keyfilePath);
        std::string baseKeyfile = p.filename().string();
        
        // Ensure the filename follows the syntax: <username>_keyfile.pem
        size_t pos = baseKeyfile.find("_keyfile.pem");
        if (pos == std::string::npos) {
            std::cerr << "Keyfile name does not follow the required format (<username>_keyfile.pem).\n";
            return "";
        }
        std::string uname = baseKeyfile.substr(0, pos);
    
        // Verify the user's root directory exists.
        std::string userRootDir = "filesystem/" + SecOps::SecurityOps::sha256(uname);
        if (!std::filesystem::exists(userRootDir)) {
            std::cerr << "User root directory not found for " << uname << "\n";
            return "";
        }
    
        // Locate the per-user mapping file by scanning the user's root directory.
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
        
        // Load the user's public key from the PUBLIC_KEYS_DIR.
        std::string pubFilePath = PUBLIC_KEYS_DIR + "/" + uname + "_public.pem";
        std::ifstream pubFile(pubFilePath);
        if (!pubFile) {
            std::cerr << "Unable to open public key file for user " << uname << "\n";
            return "";
        }
        std::stringstream pubBuf;
        pubBuf << pubFile.rdbuf();
        std::string userPub = pubBuf.str();
    
        // Cache the user in the in-memory map.
        users[uname] = User{uname, keyData, userPub, (uname == "admin")};
        return uname;
    }
    

    /**
     * mapUser:
     * Updates global_mapping.json with the user's base directory info:
     * - "root": SHA-256 hash of username.
     * - "shared": SHA-256 hash of "shared".
     * - "shared_files": an empty object.
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
     * Updates the admin mapping file (admin_mapping.json) in FILESYSTEM_DIR.
     * The file maps usernames to their private keys and is encrypted using AES with a key derived from admin's private key.
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