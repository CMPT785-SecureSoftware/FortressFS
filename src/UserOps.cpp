#include "UserOps.h"
#include "SecurityOps.h"
#include "FileOps.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
<<<<<<< HEAD
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace UOps {

std::unordered_map<std::string, User> UserOps::users;

static const std::string PRIVATE_KEYS_DIR = "private_keys";
static const std::string PUBLIC_KEYS_DIR  = "public_keys";

/**
 * createUser:
 * - Calls generateRSAKeyPair => <username>_keyfile.pem + <username>_public.pem
 * - Moves <username>_keyfile.pem => private_keys
 * - Moves <username>_public.pem => public_keys
 * - Creates hashed root in filesystem, plus hashed "personal" and "shared".
 * - mapUser => update global mapping
 * - Add to memory (isAdmin if username=="admin")
 */

/**
 * getUser:
 * returns from memory, or empty user if not found
 */
User UserOps::getUser(const std::string &username) {
    auto it = users.find(username);
    if (it != users.end()) {
        return it->second;
    }
    return User{"", "", "", false};
}

/**
 * userExists:
 * check if user is in memory
 */
bool UserOps::userExists(const std::string &username) {
    return (users.find(username) != users.end());
}

/**
 * mapUser:
 * update global_mapping.json for <username> => root, shared, shared_files
 */
bool UserOps::mapUser(const std::string &username, const std::string &publicKey) {
    json mapping;
    std::ifstream ifs("global_mapping.json");
    if (ifs) {
        ifs >> mapping;
        ifs.close();
    }
    mapping[username] = {
        {"root", SecOps::SecurityOps::sha256(username)},
        {"shared", SecOps::SecurityOps::sha256("shared")},
        {"shared_files", json::object()}
    };
    std::ofstream ofs("global_mapping.json");
    ofs << mapping.dump(4);
    return ofs.good();
}

/**
 * updateAdminMapping:
 * store user’s private key in the admin_mapping.json. 
 * That file is named sha256("admin_mapping.json") in filesystem/
 * encrypted with AES using admin's private key as 32-byte key.
 */
bool UserOps::updateAdminMapping(const std::string &username, const std::string &userPrivateKey, const std::string &adminPrivateKey) {
    std::string adminMappingFileName = SecOps::SecurityOps::sha256("admin_mapping.json");
    std::string adminMappingPath = "filesystem/" + adminMappingFileName;

    json adminMapping;
    if (Ops::FileOps::fileExists(adminMappingPath)) {
        std::string enc = Ops::FileOps::readFile(adminMappingPath);
        std::string key = adminPrivateKey.substr(0, 32);
        try {
            std::string dec = SecOps::SecurityOps::aesDecrypt(enc, key);
            adminMapping = json::parse(dec);
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

bool UserOps::createUser(const std::string &username) {
    // For example, check validity
    for (char c : username) {
        if (!std::isalnum(c) && c != '-') {
            std::cerr << "Invalid username (alnum + '-').\n";
            return false;
        }
    }
    if (!SecOps::SecurityOps::generateRSAKeyPair(username)) {
        std::cout << "Failed generating key pair for " << username << "\n";
        return false;
    }

    // read newly created keyfiles
    std::ifstream privFile(username + "_keyfile.pem");
    if (!privFile) {
        std::cerr << "Failed opening " << username << "_keyfile.pem\n";
        return false;
    }
    std::stringstream privBuf;
    privBuf << privFile.rdbuf();
    std::string userPriv = privBuf.str();
    privFile.close();

    std::ifstream pubFile(username + "_public.pem");
    if (!pubFile) {
        std::cerr << "Failed opening " << username << "_public.pem\n";
        return false;
    }
    std::stringstream pubBuf;
    pubBuf << pubFile.rdbuf();
    std::string userPub = pubBuf.str();
    pubFile.close();

    // Move <username>_keyfile.pem => private_keys
    std::filesystem::create_directories(PRIVATE_KEYS_DIR);
    std::string keyfilePath = PRIVATE_KEYS_DIR + "/" + username + "_keyfile.pem";
    if (!Ops::FileOps::writeFile(keyfilePath, userPriv)) {
        std::cout << "Failed to write " << keyfilePath << "\n";
        return false;
    }

    // Move <username>_public.pem => public_keys
    std::filesystem::create_directories(PUBLIC_KEYS_DIR);
    std::string pubDest = PUBLIC_KEYS_DIR + "/" + username + "_public.pem";
    std::filesystem::rename(username + "_public.pem", pubDest);

    // Create hashed root in filesystem
    std::string userRoot = "filesystem/" + SecOps::SecurityOps::sha256(username);
    std::filesystem::create_directories(userRoot);
    // hashed personal & shared
    std::string personalDir = userRoot + "/" + SecOps::SecurityOps::sha256("personal");
    std::string sharedDir   = userRoot + "/" + SecOps::SecurityOps::sha256("shared");
    std::filesystem::create_directories(personalDir);
    std::filesystem::create_directories(sharedDir);

    // update global mapping
    if (!UserOps::mapUser(username, userPub)) {
        std::cout << "Failed updating global mapping for " << username << "\n";
        return false;
    }

    // Add to memory
    bool adminFlag = (username == "admin");
    users[username] = User{username, userPriv, userPub, adminFlag};
    std::cout << "Created user: " << username << "\n";
    return true;
}

/**
 * login:
 * - read entire content of <keyfilePath> (which should be <username>_keyfile.pem)
 * - extract username from filename
 * - read user root directory, pick up the first non-dir file as user mapping, decrypt with key
 * - ensure mapping["username"] matches
 * - read public key from public_keys
 * - store in memory
 */
std::string UserOps::login(const std::string &keyfilePath) {
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

    // get username from the filename
    std::filesystem::path p(keyfilePath);
    std::string baseKeyfile = p.filename().string(); // e.g. "jeril_keyfile.pem"
    size_t pos = baseKeyfile.find("_keyfile.pem");
    if (pos == std::string::npos) {
        std::cerr << "Keyfile name not in <username>_keyfile.pem format\n";
        return "";
    }
    std::string uname = baseKeyfile.substr(0, pos);

    // hashed root
    std::string userRoot = "filesystem/" + SecOps::SecurityOps::sha256(uname);
    if (!std::filesystem::exists(userRoot)) {
        std::cerr << "User root not found for " << uname << "\n";
        return "";
    }

    // pick first non-directory file => user mapping
    std::string mappingFilePath;
    for (auto &entry : std::filesystem::directory_iterator(userRoot)) {
        if (!entry.is_directory()) {
            mappingFilePath = entry.path().string();
            break;
        }
    }
    if (mappingFilePath.empty()) {
        std::cerr << "No mapping file found for user " << uname << "\n";
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
        std::cerr << "Invalid JSON in mapping\n";
        return "";
    }
    if (!mapping.contains("username") || mapping["username"] != uname) {
        std::cerr << "Mapping username mismatch for " << uname << "\n";
        return "";
    }

    // read public
    std::string pubFile = PUBLIC_KEYS_DIR + "/" + uname + "_public.pem";
    std::ifstream pubF(pubFile);
    if (!pubF) {
        std::cerr << "Cannot open " << pubFile << "\n";
        return "";
    }
    std::stringstream pubBuf;
    pubBuf << pubF.rdbuf();
    std::string userPub = pubBuf.str();
    pubF.close();

    bool adminFlag = (uname == "admin");
    users[uname] = User{uname, keyData, userPub, adminFlag};
    return uname;
}

} // namespace UOps
=======

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
                                  std::istreambuf_iterator<char>());
        } else {
            keyData = std::string((std::istreambuf_iterator<char>(ifs)),
                                  std::istreambuf_iterator<char>());
        }
        if (keyData.empty())
            return "";
        
        // Check if the key data equals the admin identifier.
        if (keyData == ADMIN_IDENTIFIER) {
            if (users.find("admin") == users.end())
                users["admin"] = User{"admin", keyData, "", true};
            return "admin";
        }
        
        // Otherwise, assume the keyfile name is in the format "<username>_keyfile.pem"
        size_t pos = baseKeyfile.find("_keyfile.pem");
        if (pos != std::string::npos) {
            std::string uname = baseKeyfile.substr(0, pos);
            if (users.find(uname) == users.end()) {
                // Load the public key from the public_keys folder.
                std::ifstream pub((PUBLIC_KEYS_DIR + "/" + uname + "_public.pem").c_str());
                std::stringstream pubBuf;
                pubBuf << pub.rdbuf();
                std::string userPub = pubBuf.str();
                users[uname] = User{uname, keyData, userPub, false};
            }
            return uname;
        }
        return "";
    }
}
>>>>>>> 8874a9cf4754fcd8b285cc15a9acf5c728818402
