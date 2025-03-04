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
bool UserOps::createUser(const std::string &username) {
    // For example, check validity
    for (char c : username) {
        if (!std::isalnum(c) && c != '-') {
            std::cerr << "[Debug] Invalid username (alnum + '-').\n";  // debug only
            return false;
        }
    }
    if (!SecOps::SecurityOps::generateRSAKeyPair(username)) {
        std::cerr << "[Debug] Failed generating key pair for " << username << "\n";
        return false;
    }

    // read newly created keyfiles
    std::ifstream privFile(username + "_keyfile.pem");
    if (!privFile) {
        std::cerr << "[Debug] Failed opening " << username << "_keyfile.pem\n";
        return false;
    }
    std::stringstream privBuf;
    privBuf << privFile.rdbuf();
    std::string userPriv = privBuf.str();
    privFile.close();

    std::ifstream pubFile(username + "_public.pem");
    if (!pubFile) {
        std::cerr << "[Debug] Failed opening " << username << "_public.pem\n";
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
        std::cerr << "[Debug] Failed to write " << keyfilePath << "\n";
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
        std::cerr << "[Debug] Failed updating global mapping for " << username << "\n";
        return false;
    }

    // Add to memory
    bool adminFlag = (username == "admin");
    users[username] = User{username, userPriv, userPub, adminFlag};
    std::cout << "Created user: " << username << "\n";  // user-facing success message
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
 *
 * If any check fails, we simply return "".
 * We do not print user-facing errors. We log to std::cerr for debugging only.
 */
std::string UserOps::login(const std::string &keyfilePath) {
    // Attempt reading the entire keyfile content
    std::ifstream ifs(keyfilePath, std::ios::binary);
    if (!ifs) {
        std::cerr << "[Debug] Unable to open keyfile: " << keyfilePath << "\n";
        return "";
    }
    std::string keyData((std::istreambuf_iterator<char>(ifs)),
                        std::istreambuf_iterator<char>());
    ifs.close();
    if (keyData.empty()) {
        std::cerr << "[Debug] Keyfile is empty: " << keyfilePath << "\n";
        return "";
    }

    // get username from the filename <username>_keyfile.pem
    std::filesystem::path p(keyfilePath);
    std::string baseKeyfile = p.filename().string(); 
    size_t pos = baseKeyfile.find("_keyfile.pem");
    if (pos == std::string::npos) {
        std::cerr << "[Debug] Keyfile name not in <username>_keyfile.pem format\n";
        return "";
    }
    std::string uname = baseKeyfile.substr(0, pos);

    // hashed root
    std::string userRoot = "filesystem/" + SecOps::SecurityOps::sha256(uname);
    if (!std::filesystem::exists(userRoot)) {
        std::cerr << "[Debug] User root not found for " << uname << "\n";
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
        std::cerr << "[Debug] No mapping file found for user " << uname << "\n";
        return "";
    }

    std::string encryptedMapping = Ops::FileOps::readFile(mappingFilePath);
    std::string decryptedMapping;
    try {
        decryptedMapping = SecOps::SecurityOps::rsaDecrypt(encryptedMapping, keyData);
    } catch (std::exception &e) {
        std::cerr << "[Debug] User mapping decryption failed for " << uname 
                  << ": " << e.what() << "\n";
        return "";
    }
    json mapping;
    try {
        mapping = json::parse(decryptedMapping);
    } catch (...) {
        std::cerr << "[Debug] Invalid JSON in mapping for user " << uname << "\n";
        return "";
    }
    if (!mapping.contains("username") || mapping["username"] != uname) {
        std::cerr << "[Debug] Mapping username mismatch for " << uname << "\n";
        return "";
    }

    // read public
    std::string pubFile = PUBLIC_KEYS_DIR + "/" + uname + "_public.pem";
    std::ifstream pubF(pubFile);
    if (!pubF) {
        std::cerr << "[Debug] Cannot open public key " << pubFile << " for user " << uname << "\n";
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
    if (!ofs.good()) {
        std::cerr << "[Debug] mapUser: writing global_mapping failed.\n";
        return false;
    }
    return true;
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
    bool success = Ops::FileOps::writeFile(adminMappingPath, encrypted);
    if(!success) {
        std::cerr << "[Debug] updateAdminMapping: writeFile failed for " << adminMappingPath << "\n";
    }
    return success;
}

} // namespace UOps
