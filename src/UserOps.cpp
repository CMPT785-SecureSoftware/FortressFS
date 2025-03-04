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
static const std::string ADMIN_KEYS_DIR   = "admin_keys"; // For admin's final private key location

/**
 * createUserFileMapping:
 * Creates a JSON object describing the user_file_mapping (root folder, personal folder, etc.),
 * then encrypts it using a hybrid approach.
 * The hybridEncrypt function generates a random AES key, encrypts the plaintext with AES,
 * then encrypts the AES key with RSA (using the user's public key).
 * The output is stored as the file named sha256("user_file_mapping.json") under filesystem/<sha256(username)>.
 */
bool UserOps::createUserFileMapping(const std::string &username, const std::string &userPub) {
    std::string userRoot = "filesystem/" + SecOps::SecurityOps::sha256(username);
    if (!std::filesystem::exists(userRoot)) {
        Ops::FileOps::appendErrorLog("[Debug] createUserFileMapping: user root doesn't exist for " + username);
        return false;
    }
    json mapping;
    mapping["username"] = username;
    mapping["root"]     = SecOps::SecurityOps::sha256(username);
    mapping["personal"] = SecOps::SecurityOps::sha256("personal");
    mapping["entries"]  = json::object();  // To track subfolders/files in personal

    std::string fileNameHash = SecOps::SecurityOps::sha256("user_file_mapping.json");
    std::string filePath = userRoot + "/" + fileNameHash;
    std::string plain = mapping.dump(4);
    std::string encrypted;
    try {
        // Use hybrid encryption: encrypt plain using a random AES key and RSA encrypt that AES key.
        encrypted = SecOps::SecurityOps::hybridEncrypt(plain, userPub);
    } catch(std::exception &e) {
        Ops::FileOps::appendErrorLog("[Debug] createUserFileMapping: hybridEncrypt failed: " + std::string(e.what()));
        return false;
    }
    if (!Ops::FileOps::writeFile(filePath, encrypted)) {
        Ops::FileOps::appendErrorLog("[Debug] createUserFileMapping: writeFile failed for " + filePath);
        return false;
    }
    return true;
}

/**
 * loadUserFileMappingPublic:
 * Public method to load and decrypt the user's file mapping.
 * Reads the encrypted file from filesystem/<sha256(username)>/<sha256("user_file_mapping.json")>,
 * then uses hybridDecrypt (which first RSA-decrypts the AES key with the user's private key,
 * and then uses that AES key to decrypt the actual JSON mapping).
 * Returns an empty JSON object if any step fails.
 */
json UserOps::loadUserFileMappingPublic(const std::string &username, const std::string &userPriv) {
    json empty;
    std::string userRoot = "filesystem/" + SecOps::SecurityOps::sha256(username);
    std::string fileNameHash = SecOps::SecurityOps::sha256("user_file_mapping.json");
    std::string filePath = userRoot + "/" + fileNameHash;
    if (!Ops::FileOps::fileExists(filePath)) {
        Ops::FileOps::appendErrorLog("[Debug] loadUserFileMappingPublic: file does not exist " + filePath);
        return empty;
    }
    std::string encData = Ops::FileOps::readFile(filePath);
    if (encData.empty()) {
        Ops::FileOps::appendErrorLog("[Debug] loadUserFileMappingPublic: empty file " + filePath);
        return empty;
    }
    std::string decrypted;
    try {
        decrypted = SecOps::SecurityOps::hybridDecrypt(encData, userPriv);
    } catch(std::exception &e) {
        Ops::FileOps::appendErrorLog("[Debug] loadUserFileMappingPublic: hybridDecrypt failed: " + std::string(e.what()));
        return empty;
    }
    json j;
    try {
        j = json::parse(decrypted);
    } catch(...) {
        Ops::FileOps::appendErrorLog("[Debug] loadUserFileMappingPublic: JSON parse error for " + filePath);
        return empty;
    }
    return j;
}

/**
 * saveUserFileMappingPublic:
 * Helper to re-encrypt and save the user's file mapping.
 * Uses hybridEncrypt to encrypt the mapping JSON (after dumping it as a string) with the user's public key.
 */
bool UserOps::saveUserFileMappingPublic(const std::string &username, const std::string &userPub, const json &mapping) {
    std::string userRoot = "filesystem/" + SecOps::SecurityOps::sha256(username);
    std::string fileNameHash = SecOps::SecurityOps::sha256("user_file_mapping.json");
    std::string filePath = userRoot + "/" + fileNameHash;
    std::string plain = mapping.dump(4);
    std::string encrypted;
    try {
        encrypted = SecOps::SecurityOps::hybridEncrypt(plain, userPub);
    } catch(std::exception &e) {
        Ops::FileOps::appendErrorLog("[Debug] saveUserFileMappingPublic: hybridEncrypt failed: " + std::string(e.what()));
        return false;
    }
    if (!Ops::FileOps::writeFile(filePath, encrypted)) {
        Ops::FileOps::appendErrorLog("[Debug] saveUserFileMappingPublic: writeFile failed for " + filePath);
        return false;
    }
    return true;
}

/**
 * createUser:
 * - Generates RSA key pair (<username>_keyfile.pem, <username>_public.pem).
 * - Moves the keyfiles to private_keys and public_keys respectively.
 * - Creates a hashed root directory (filesystem/<sha256(username)>) and subdirectories for "personal" and "shared".
 * - Creates the encrypted user_file_mapping.json in the user's root.
 * - Updates global_mapping.json with the user's info.
 * - Adds the user to the in-memory cache.
 */
bool UserOps::createUser(const std::string &username) {
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
    // Read keyfiles.
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
    // Move keyfiles.
    std::filesystem::create_directories(PRIVATE_KEYS_DIR);
    std::string keyfilePath = PRIVATE_KEYS_DIR + "/" + username + "_keyfile.pem";
    if (!Ops::FileOps::writeFile(keyfilePath, userPriv)) {
        Ops::FileOps::appendErrorLog("[Debug] Could not write " + keyfilePath);
        return false;
    }
    std::filesystem::create_directories(PUBLIC_KEYS_DIR);
    std::string pubDest = PUBLIC_KEYS_DIR + "/" + username + "_public.pem";
    std::filesystem::rename(username + "_public.pem", pubDest);
    // Create hashed user root.
    std::string userRoot = "filesystem/" + SecOps::SecurityOps::sha256(username);
    std::filesystem::create_directories(userRoot);
    // Create subdirectories "personal" and "shared".
    std::string personalDir = userRoot + "/" + SecOps::SecurityOps::sha256("personal");
    std::string sharedDir   = userRoot + "/" + SecOps::SecurityOps::sha256("shared");
    std::filesystem::create_directories(personalDir);
    std::filesystem::create_directories(sharedDir);
    // Create the encrypted user_file_mapping.
    if (!createUserFileMapping(username, userPub)) {
        Ops::FileOps::appendErrorLog("[Debug] createUser: createUserFileMapping failed for " + username);
        return false;
    }
    // Update global mapping.
    if (!UserOps::mapUser(username, userPub)) {
        Ops::FileOps::appendErrorLog("[Debug] createUser: mapUser failed for " + username);
        return false;
    }
    bool adminFlag = (username == "admin");
    if (adminFlag) {
        if (!UOps::UserOps::updateAdminMapping(username, userPriv, userPub)) {
            Ops::FileOps::appendErrorLog("[Debug] Failed to update admin mapping for " + username);
        }
    }
    users[username] = User{username, userPriv, userPub, adminFlag};
    return true;
}

/**
 * login:
 * - Reads the entire keyfile.
 * - Extracts the username from the keyfile name (<username>_keyfile.pem).
 * - Loads and decrypts the user_file_mapping using the keyfile content via hybrid decryption.
 * - Verifies that the mapping contains the correct username.
 * - Reads the corresponding public key.
 * - Caches the user in memory and returns the username.
 * - Returns an empty string if any step fails.
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
    std::filesystem::path p(keyfilePath);
    std::string baseKeyfile = p.filename().string();
    size_t pos = baseKeyfile.find("_keyfile.pem");
    if (pos == std::string::npos) {
        Ops::FileOps::appendErrorLog("[Debug] Keyfile name not in <username>_keyfile.pem format: " + baseKeyfile);
        return "";
    }
    std::string uname = baseKeyfile.substr(0, pos);
    std::string userRoot = "filesystem/" + SecOps::SecurityOps::sha256(uname);
    if (!std::filesystem::exists(userRoot)) {
        Ops::FileOps::appendErrorLog("[Debug] login: user root not found for " + uname);
        return "";
    }
    // Load the user_file_mapping using hybrid decryption.
    json mapping = loadUserFileMappingPublic(uname, keyData);
    if (mapping.empty()) {
        Ops::FileOps::appendErrorLog("[Debug] login: user_file_mapping is empty for " + uname);
        return "";
    }
    if (!mapping.contains("username") || mapping["username"] != uname) {
        Ops::FileOps::appendErrorLog("[Debug] login: mismatch in user_file_mapping for " + uname);
        return "";
    }
    // Read the user's public key.
    std::string pubFilePath = PUBLIC_KEYS_DIR + "/" + uname + "_public.pem";
    std::ifstream pubF(pubFilePath);
    if (!pubF) {
        Ops::FileOps::appendErrorLog("[Debug] login: cannot open public key for " + uname);
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
 * Updates global_mapping.json for the given user with:
 * - root: hashed username.
 * - shared: hashed "shared".
 * - shared_files: an empty object for later shared file entries.
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
 * Stores the user's private key in admin_mapping.json (named as sha256("admin_mapping.json"))
 * in the filesystem, encrypted using admin's private key (first 32 bytes used as AES key).
 */
bool UserOps::updateAdminMapping(const std::string &username, const std::string &userPrivateKey, const std::string &adminPrivateKey) {
    // The admin mapping file is stored under "filesystem/" with a filename of sha256("admin_mapping.json")
    std::string adminMappingFileName = SecOps::SecurityOps::sha256("admin_mapping.json");
    std::string adminMappingPath = "filesystem/" + adminMappingFileName;
    json adminMapping;
    
    // If the admin mapping file exists, decrypt it using hybrid decryption with admin's private key.
    if (Ops::FileOps::fileExists(adminMappingPath)) {
        std::string enc = Ops::FileOps::readFile(adminMappingPath);
        try {
            std::string dec = SecOps::SecurityOps::hybridDecrypt(enc, adminPrivateKey);
            adminMapping = json::parse(dec);
        } catch (...) {
            adminMapping = json::object();
        }
    }
    // Update mapping: store the new user's private key.
    adminMapping[username] = userPrivateKey;
    std::string plain = adminMapping.dump(4);

    // Read admin's public key from file.
    std::ifstream adminPubStream("public_keys/admin_public.pem");
    if (!adminPubStream) {
        Ops::FileOps::appendErrorLog("[Debug] updateAdminMapping: failed to open admin public key file");
        return false;
    }
    std::stringstream adminPubBuf;
    adminPubBuf << adminPubStream.rdbuf();
    std::string adminPub = adminPubBuf.str();
    adminPubStream.close();

    // Encrypt the mapping using hybrid encryption with admin's public key.
    std::string encrypted;
    try {
        encrypted = SecOps::SecurityOps::hybridEncrypt(plain, adminPub);
    } catch(std::exception &e) {
        Ops::FileOps::appendErrorLog("[Debug] updateAdminMapping: hybridEncrypt failed: " + std::string(e.what()));
        return false;
    }
    bool success = Ops::FileOps::writeFile(adminMappingPath, encrypted);
    if (!success) {
        Ops::FileOps::appendErrorLog("[Debug] updateAdminMapping: writeFile failed for " + adminMappingPath);
    }
    return success;
}

} // namespace UOps
