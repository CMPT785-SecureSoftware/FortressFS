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
static const std::string ADMIN_KEYS_DIR   = "admin_keys";   // for admin's final private key location

/**
 * createUserFileMapping:
 * Creates a JSON object describing the user_file_mapping (root folder, personal folder).
 * Then encrypts it with userPub and writes it to userRoot + "/" + sha256("user_file_mapping.json").
 */
bool UserOps::createUserFileMapping(const std::string &username, const std::string &userPub) {
    std::string userRoot = "filesystem/" + SecOps::SecurityOps::sha256(username);
    if (!std::filesystem::exists(userRoot)) {
        Ops::FileOps::appendErrorLog("[Debug] createUserFileMapping: user root doesn't exist for " + username);
        return false;
    }

    json mapping;
    mapping["username"] = username;
    mapping["root"] = SecOps::SecurityOps::sha256(username);
    mapping["personal"] = SecOps::SecurityOps::sha256("personal");
    // We'll also have a subobject "entries" for personal subfolders/files if needed
    mapping["entries"] = json::object();

    std::string fileNameHash = SecOps::SecurityOps::sha256("user_file_mapping.json");
    std::string filePath = userRoot + "/" + fileNameHash;

    std::string plain = mapping.dump(4);
    std::string encrypted;
    try {
        encrypted = SecOps::SecurityOps::rsaEncrypt(plain, userPub);
    } catch(std::exception &e) {
        Ops::FileOps::appendErrorLog("[Debug] createUserFileMapping: rsaEncrypt failed: " + std::string(e.what()));
        return false;
    }
    if (!Ops::FileOps::writeFile(filePath, encrypted)) {
        Ops::FileOps::appendErrorLog("[Debug] createUserFileMapping: writeFile failed for " + filePath);
        return false;
    }
    return true;
}

/**
 * loadUserFileMapping:
 * Reads encrypted user_file_mapping from the hashed file, decrypts with userPriv, returns the JSON.
 * Returns empty if anything fails.
 */
json UserOps::loadUserFileMapping(const std::string &username, const std::string &userPriv) {
    json empty;
    std::string userRoot = "filesystem/" + SecOps::SecurityOps::sha256(username);
    std::string fileNameHash = SecOps::SecurityOps::sha256("user_file_mapping.json");
    std::string filePath = userRoot + "/" + fileNameHash;
    if (!Ops::FileOps::fileExists(filePath)) {
        Ops::FileOps::appendErrorLog("[Debug] loadUserFileMapping: file does not exist " + filePath);
        return empty;
    }
    std::string encData = Ops::FileOps::readFile(filePath);
    if (encData.empty()) {
        Ops::FileOps::appendErrorLog("[Debug] loadUserFileMapping: empty file " + filePath);
        return empty;
    }
    std::string decrypted;
    try {
        decrypted = SecOps::SecurityOps::rsaDecrypt(encData, userPriv);
    } catch(std::exception &e) {
        Ops::FileOps::appendErrorLog("[Debug] loadUserFileMapping: rsaDecrypt failed: " + std::string(e.what()));
        return empty;
    }
    json j;
    try {
        j = json::parse(decrypted);
    } catch(...) {
        Ops::FileOps::appendErrorLog("[Debug] loadUserFileMapping: JSON parse error for " + filePath);
        return empty;
    }
    return j;
}

/**
 * createUser:
 *  1) generateRSAKeyPair => <username>_keyfile.pem, <username>_public.pem
 *  2) move private => private_keys, public => public_keys
 *  3) if (username=="admin"), we eventually want it in admin_keys/admin_keyfile.pem, but that can be done outside or you can do it here.
 *  4) create hashed root, personal, shared
 *  5) create user_file_mapping
 *  6) update global mapping
 *  7) store user in memory
 */
bool UserOps::createUser(const std::string &username) {
    // Validate
    for (char c : username) {
        if (!std::isalnum(c) && c != '-') {
            Ops::FileOps::appendErrorLog("[Debug] Invalid username: " + username);
            return false;
        }
    }
    if (!SecOps::SecurityOps::generateRSAKeyPair(username)) {
        Ops::FileOps::appendErrorLog("[Debug] Failed generating key pair for " + username);
        return false;
    }

    // read newly created keyfiles
    std::ifstream privFile(username + "_keyfile.pem");
    if (!privFile) {
        Ops::FileOps::appendErrorLog("[Debug] Failed opening " + username + "_keyfile.pem");
        return false;
    }
    std::stringstream privBuf;
    privBuf << privFile.rdbuf();
    std::string userPriv = privBuf.str();
    privFile.close();

    std::ifstream pubFile(username + "_public.pem");
    if (!pubFile) {
        Ops::FileOps::appendErrorLog("[Debug] Failed opening " + username + "_public.pem");
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
        Ops::FileOps::appendErrorLog("[Debug] Could not write " + keyfilePath);
        return false;
    }

    // Move <username>_public.pem => public_keys
    std::filesystem::create_directories(PUBLIC_KEYS_DIR);
    std::string pubDest = PUBLIC_KEYS_DIR + "/" + username + "_public.pem";
    std::filesystem::rename(username + "_public.pem", pubDest);

    // Create hashed root => /filesystem/<sha256(username)>
    std::string userRoot = "filesystem/" + SecOps::SecurityOps::sha256(username);
    std::filesystem::create_directories(userRoot);

    // hashed personal & shared
    std::string personalDir = userRoot + "/" + SecOps::SecurityOps::sha256("personal");
    std::string sharedDir   = userRoot + "/" + SecOps::SecurityOps::sha256("shared");
    std::filesystem::create_directories(personalDir);
    std::filesystem::create_directories(sharedDir);

    // Create user_file_mapping
    if (!createUserFileMapping(username, userPub)) {
        Ops::FileOps::appendErrorLog("[Debug] createUser: createUserFileMapping failed for " + username);
        return false;
    }

    // update global mapping
    if (!UserOps::mapUser(username, userPub)) {
        Ops::FileOps::appendErrorLog("[Debug] createUser: mapUser failed for " + username);
        return false;
    }

    // is admin?
    bool adminFlag = (username == "admin");
    // store user in memory
    users[username] = User{username, userPriv, userPub, adminFlag};

    // If admin, we might do additional steps for admin, e.g. store in admin_mapping.
    // But typically that's done outside or with adduser logic. 
    // We'll just print success for normal or admin user:
    std::cout << "Created user: " << username << "\n";
    return true;
}

/**
 * login:
 *  1) read entire <keyfilePath> => userPriv
 *  2) extract <username> from it
 *  3) load user_file_mapping for that user => decrypt with userPriv
 *  4) confirm mapping["username"] == <username>
 *  5) read userPub from public_keys
 *  6) store in memory
 *  7) return username or ""
 */
std::string UserOps::login(const std::string &keyfilePath) {
    std::ifstream ifs(keyfilePath, std::ios::binary);
    if (!ifs) {
        Ops::FileOps::appendErrorLog("[Debug] Unable to open keyfile: " + keyfilePath);
        return "";
    }
    std::string keyData((std::istreambuf_iterator<char>(ifs)),
                        std::istreambuf_iterator<char>());
    ifs.close();
    if (keyData.empty()) {
        Ops::FileOps::appendErrorLog("[Debug] Keyfile is empty: " + keyfilePath);
        return "";
    }

    // parse username from <username>_keyfile.pem
    std::filesystem::path p(keyfilePath);
    std::string baseKeyfile = p.filename().string();
    size_t pos = baseKeyfile.find("_keyfile.pem");
    if (pos == std::string::npos) {
        Ops::FileOps::appendErrorLog("[Debug] Keyfile name not in <username>_keyfile.pem format: " + baseKeyfile);
        return "";
    }
    std::string uname = baseKeyfile.substr(0, pos);

    // hashed root
    std::string userRoot = "filesystem/" + SecOps::SecurityOps::sha256(uname);
    if (!std::filesystem::exists(userRoot)) {
        Ops::FileOps::appendErrorLog("[Debug] User root not found for " + uname);
        return "";
    }

    // load user_file_mapping
    json mapping = loadUserFileMapping(uname, keyData);
    if (mapping.empty()) {
        Ops::FileOps::appendErrorLog("[Debug] login: user_file_mapping empty for " + uname);
        return "";
    }
    if (!mapping.contains("username") || mapping["username"] != uname) {
        Ops::FileOps::appendErrorLog("[Debug] login: mismatch in username inside user_file_mapping for " + uname);
        return "";
    }

    // read user's public key
    std::string pubFilePath = PUBLIC_KEYS_DIR + "/" + uname + "_public.pem";
    std::ifstream pubFile(pubFilePath);
    if (!pubFile) {
        Ops::FileOps::appendErrorLog("[Debug] login: cannot open public key for " + uname);
        return "";
    }
    std::stringstream pubBuf;
    pubBuf << pubFile.rdbuf();
    std::string userPub = pubBuf.str();
    pubFile.close();

    bool adminFlag = (uname == "admin");
    users[uname] = User{uname, keyData, userPub, adminFlag};
    return uname;
}

bool UserOps::userExists(const std::string &username) {
    return (users.find(username) != users.end());
}

User UserOps::getUser(const std::string &username) {
    auto it = users.find(username);
    if (it != users.end()) {
        return it->second;
    }
    return User{"", "", "", false};
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
        Ops::FileOps::appendErrorLog("[Debug] mapUser: writing global_mapping.json failed for user " + username);
        return false;
    }
    return true;
}

/**
 * updateAdminMapping:
 * store user’s private key in the admin_mapping.json
 * (We do not remove this if we want the admin to have read-only access to user private keys.)
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
    std::string encrypted;
    try {
        encrypted = SecOps::SecurityOps::aesEncrypt(plain, key);
    } catch(std::exception &e) {
        Ops::FileOps::appendErrorLog("[Debug] updateAdminMapping: aesEncrypt failed: " + std::string(e.what()));
        return false;
    }
    bool success = Ops::FileOps::writeFile(adminMappingPath, encrypted);
    if(!success) {
        Ops::FileOps::appendErrorLog("[Debug] updateAdminMapping: writeFile failed for " + adminMappingPath);
    }
    return success;
}

} // namespace UOps