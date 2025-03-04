#include "UserOps.h"
#include "SecurityOps.h"
#include "FileOps.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace {
    // Load the global mapping (combined from old user_mapping and naming mapping).
    static json loadGlobalMapping() {
        std::ifstream ifs("global_mapping.json");
        if (!ifs) return json::object();
        json j;
        ifs >> j;
        return j;
    }
    // Save the global mapping.
    static bool saveGlobalMapping(const json &j) {
        std::ofstream ofs("global_mapping.json");
        ofs << j.dump(4);
        return ofs.good();
    }
}


namespace UOps {

    std::unordered_map<std::string, User> UserOps::users;

    // Constants for key storage folders.
    static const std::string PRIVATE_KEYS_DIR = "private_keys";     // For user private keys
    static const std::string PUBLIC_KEYS_DIR = "public_keys";         // For public keys

    // Fixed admin key identifier for login purposes.
    // In our design, the admin's private key is stored in admin_keys.
    // For login, if the key file content equals "ADMIN_PRIV", we log in as admin.
    // (Alternatively, we can compare with the actual admin private key read from disk.)
    static const std::string ADMIN_IDENTIFIER = "ADMIN_PRIV";

    // createUser() is called by the admin (via adduser) to create a new user.
    bool UserOps::createUser(const std::string &username) {
        // Validate the username: alphanumeric and hyphen only.
        for (char c : username) {
            if (!std::isalnum(c) && c != '-') {
                std::cerr << "Invalid username. Only alphanumeric characters and hyphen are allowed.\n";
                return false;
            }
        }
        
        // Check if the user already exists.
        if (userExists(username)) {
            std::cout << "User " << username << " already exists\n";
            return false;
        }
        // Generate RSA key pair for the user.
        if (!SecOps::SecurityOps::generateRSAKeyPair(username)) {
            std::cout << "Failed to generate key pair for " << username << "\n";
            return false;
        }
        // Read the user's private key from the generated file.
        std::ifstream privFile(username + "_private.pem");
        std::stringstream privBuf;
        privBuf << privFile.rdbuf();
        std::string userPriv = privBuf.str();

        // Read the user's public key.
        std::ifstream pubFile(username + "_public.pem");
        std::stringstream pubBuf;
        pubBuf << pubFile.rdbuf();
        std::string userPub = pubBuf.str();

        // Move the private key to the private_keys folder.
        std::filesystem::create_directories(PRIVATE_KEYS_DIR);
        std::string keyfilePath = PRIVATE_KEYS_DIR + "/" + username + "_keyfile.pem";
        if (!Ops::FileOps::writeFile(keyfilePath, userPriv)) {
            std::cout << "Failed to write user keyfile\n";
            return false;
        }
        // Move the public key to the public_keys folder.
        std::filesystem::create_directories(PUBLIC_KEYS_DIR);
        std::string pubDest = PUBLIC_KEYS_DIR + "/" + username + "_public.pem";
        std::filesystem::rename(username + "_public.pem", pubDest);

        // Create the user record.
        users[username] = User{username, userPriv, userPub, false};

        std::cout << "Created user: " << username << "\n";
        std::filesystem::remove(username+"_public.pem");
        
        // Create the per-user file mapping (for personal folder) in the user's root.
        // This file will contain at least: {"username": "<username>", "files": {} }
        json userMapping;
        userMapping["username"] = username;
        userMapping["files"] = json::object();
        std::string mappingStr = userMapping.dump(4);
        // Encrypt the mapping string with the user's public key.
        std::string encryptedMapping = SecOps::SecurityOps::rsaEncrypt(mappingStr, userPub);
        // Store this file in the user's root folder.
        std::string userRootDir = "filesystem/" + SecOps::SecurityOps::sha256(username);
        std::filesystem::create_directories(userRootDir);
        // Compute the mapping file name as the hash of "<username>_file_mapping.json".
        std::string mappingFileName = SecOps::SecurityOps::sha256(username + "_file_mapping.json");
        std::string mappingFilePath = userRootDir + "/" + mappingFileName;
        Ops::FileOps::writeFile(mappingFilePath, encryptedMapping);

        // Use the mapUser function to update global_mapping.json.
        if (!UserOps::mapUser(username, userPub)) {
            std::cout << "Failed to update user mapping for " << username << "\n";
            return false;
        }
        return true;
    }

    // getUser returns the in-memory record.
    User UserOps::getUser(const std::string &username) {
        if (users.find(username) != users.end())
            return users[username];
        return User{"", "", "", false};
    }

    // login() attempts to log in using the provided keyfile.
    // It reads the keyfile (plaintext PEM), and then, if successful,
    // then reading and decrypting the user_file_mapping.json from the user's root.
    std::string UserOps::login(const std::string &keyfilePath) {
        // Extract only the filename portion from the provided keyfile path.
        std::filesystem::path p(keyfilePath);
        std::string baseKeyfile = p.filename().string();

        std::string keyData;
        // Try reading the keyfile from the provided path.
        std::ifstream ifs(keyfilePath, std::ios::binary);
        if (!ifs) {
            // If not found, try in the private_keys folder.
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

        // Determine the path for the user's mapping file.
        std::string userRootDir = "filesystem/" + SecOps::SecurityOps::sha256(uname);
        // Compute the mapping file name as the hash of "<username>_file_mapping.json".
        std::string mappingFileName = SecOps::SecurityOps::sha256(username + "_file_mapping.json");
        std::string mappingFilePath = userRootDir + "/" + mappingFileName;
        if (!std::filesystem::exists(mappingFilePath)) {
            std::cerr << "User mapping file not found for " << uname << "\n";
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
        // Parse the decrypted JSON.
        json mapping;
        try {
            mapping = json::parse(decryptedMapping);
        } catch (...) {
            std::cerr << "Failed to parse user mapping JSON\n";
            return "";
        }
        // Check that the mapping file confirms the username.
        if (!mapping.contains("username") || mapping["username"] != uname) {
            std::cerr << "User mapping does not match for " << uname << "\n";
            return "";
        }
        // If all is well, register the user.
        if (users.find(uname) == users.end()) {
            std::ifstream pub((std::string("public_keys/") + "/" + uname + "_public.pem").c_str());
            std::stringstream pubBuf;
            pubBuf << pub.rdbuf();
            std::string userPub = pubBuf.str();
            users[uname] = User{uname, keyData, userPub, false};
        }
        return uname;
    }

    // mapUser updates the global mapping (global_mapping.json) for a given user.
    // It stores the hashed root and hashed shared folder names.
    bool UserOps::mapUser(const std::string &username, const std::string &publicKey) {
        json mapping = loadGlobalMapping();
        // For each user, store an object with "root", "shared" and an empty "shared_files" mapping.
        mapping[username] = {
            { "root", SecOps::SecurityOps::sha256(username) },
            { "shared", SecOps::SecurityOps::sha256("shared") },
            { "shared_files", json::object() }
        };
        return saveGlobalMapping(mapping);
    }
}