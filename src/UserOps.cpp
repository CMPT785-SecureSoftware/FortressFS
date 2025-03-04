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

    // In-memory user cache.
    std::unordered_map<std::string, User> UserOps::users;
    static const std::string PRIVATE_KEYS_DIR = "private_keys";
    static const std::string PUBLIC_KEYS_DIR = "public_keys";

    /**
     * createUser:
     *  - Validates the username.
     *  - Generates RSA key pairs.
     *  - Moves keyfiles to appropriate directories.
     *  - Creates the per-user mapping file (named as hash("<username>_file_mapping.json"))
     *    in the user's root directory.
     *  - Updates the global mapping.
     */
    bool UserOps::createUser(const std::string &username) {
        // Validate username characters.
        for (char c : username) {
            if (!std::isalnum(c) && c != '-') {
                std::cerr << "Invalid username. Only alphanumeric characters and hyphen are allowed.\n";
                return false;
            }
        }
        // Generate RSA key pair.
        if (!SecOps::SecurityOps::generateRSAKeyPair(username)) {
            std::cout << "Failed to generate key pair for " << username << "\n";
            return false;
        }
        // Read the generated private key.
        std::ifstream privFile(username + "_private.pem");
        std::stringstream privBuf;
        privBuf << privFile.rdbuf();
        std::string userPriv = privBuf.str();

        // Read the generated public key.
        std::ifstream pubFile(username + "_public.pem");
        std::stringstream pubBuf;
        pubBuf << pubFile.rdbuf();
        std::string userPub = pubBuf.str();

        // Save private key to private_keys folder.
        std::filesystem::create_directories(PRIVATE_KEYS_DIR);
        std::string keyfilePath = PRIVATE_KEYS_DIR + "/" + username + "_keyfile.pem";
        if (!Ops::FileOps::writeFile(keyfilePath, userPriv)) {
            std::cout << "Failed to write user keyfile\n";
            return false;
        }
        // Move public key to public_keys folder.
        std::filesystem::create_directories(PUBLIC_KEYS_DIR);
        std::string pubDest = PUBLIC_KEYS_DIR + "/" + username + "_public.pem";
        std::filesystem::rename(username + "_public.pem", pubDest);

        // Store the user in memory.
        users[username] = User{username, userPriv, userPub, false};
        std::cout << "Created user: " << username << "\n";
        std::filesystem::remove(username + "_public.pem");

        // Create per-user mapping file.
        std::string userRootDir = "filesystem/" + SecOps::SecurityOps::sha256(username);
        std::filesystem::create_directories(userRootDir);
        json userMapping;
        userMapping["username"] = username;
        userMapping["files"] = json::object();
        std::string mappingStr = userMapping.dump(4);
        // Encrypt mapping using user's public key.
        std::string encryptedMapping = SecOps::SecurityOps::rsaEncrypt(mappingStr, userPub);
        // Compute the mapping file name as hash("<username>_file_mapping.json")
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

    // getUser: Returns the user from the in-memory cache.
    User UserOps::getUser(const std::string &username) {
        if (users.find(username) != users.end())
            return users[username];
        return User{"", "", "", false};
    }

    /**
     * login:
     *  - Reads the provided keyfile to obtain the private key.
     *  - Determines the username from the keyfile name.
     *  - Scans the user's hashed root directory for the single mapping file.
     *  - Decrypts the file using the provided private key.
     *  - Verifies that the decrypted JSON contains the correct username.
     *  - Loads the corresponding public key from disk and stores the user in memory.
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
            if (!entry.is_directory()) { // Should be the only file in root.
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
        // Load the public key from disk.
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
     * Updates the global mapping file (global_mapping.json) with the base directory hashes
     * for the user (root and shared) and initializes an empty mapping for shared_files.
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
}