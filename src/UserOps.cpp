#include "UserOps.h"
#include "SecurityOps.h"
#include "FileOps.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

static json loadUserMapping() {
    std::ifstream ifs("user_mapping.json");
    if (!ifs) return json::object();
    json j;
    ifs >> j;
    return j;
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
        
        json mapping = loadUserMapping();
        // Encrypt the root folder name (we assume the root folder is simply the username).
        std::string encRoot = SecurityOps::rsaEncrypt(username, userPub);
        // Encrypt the shared folder name ("shared").
        std::string encShared = SecurityOps::rsaEncrypt("shared", userPub);
        // Store both in the JSON mapping under the key for this user.
        mapping[username] = json::array({ encRoot, encShared });
        // Write back the JSON file.
        std::ofstream ofs("user_mapping.json");
        ofs << mapping.dump(4);
        ofs.close();


        return true;
    }

    bool UserOps::userExists(const std::string &username) {
        return (users.find(username) != users.end());
    }

    User UserOps::getUser(const std::string &username) {
        if (userExists(username))
            return users[username];
        return User{"", "", "", false};
    }

    // login() attempts to log in using the provided keyfile.
    // It reads the keyfile (plaintext PEM), and then, if it matches the admin identifier,
    // logs in as admin; otherwise, it extracts the username from the filename.
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
                                  std::istreambuf_iterator<f>());
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

        // Load the JSON mapping file.
        json mapping = loadUserMapping();
        if (!mapping.contains(uname)) {
            std::cerr << "No mapping for user " << uname << "\n";
            return "";
        }
        std::string encFolderName = mapping[uname][0]; // Encrypted folder name.
        try {
            // Attempt to decrypt using RSA with the user's private key.
            std::string decryptedFolder = SecurityOps::rsaDecrypt(encFolderName, keyData);
            // Compare decryptedFolder with the expected folder name (for example, simply the username).
            if (decryptedFolder != uname) {
                std::cerr << "Folder name decryption mismatch\n";
                return "";
            }
        } catch (std::exception &e) {
            std::cerr << "User verification failed: " << e.what() << "\n";
            return "";
        }
        // If all is well, register the user.
        if (users.find(uname) == users.end()) {
            // Load public key from public_keys folder, etc.
            // (Similar to previous logic)
            users[uname] = User{uname, keyData, /*load public key*/, false};
        }
        return uname;
    }
}