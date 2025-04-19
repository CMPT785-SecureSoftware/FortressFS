#include "UserOps.h"
#include "SecurityOps.h"
#include "FileOps.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <vector>
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


 // Helper function to convert bytes string to hex
 static std::string bytesToHex(const std::string &bytes) {
    std::ostringstream oss;
    for (unsigned char c : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return oss.str();
}
}

// Helper function to convert hex to bytes string
std::vector<unsigned char> UserOps::hexToBytes(const std::string &hex) {
    if (hex.size() % 2) throw std::runtime_error("Invalid hex length");
    std::vector<unsigned char> out; out.reserve(hex.size()/2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hex.substr(i,2);
        ss >> byte;
        out.push_back(static_cast<unsigned char>(byte));
    }
    return out;
}

bool UserOps::createUserFileMapping(const std::string &username, const std::string &userPub) {
    std::string userRoot = "filesystem/" + SecOps::SecurityOps::sha256(username);
    if (!std::filesystem::exists(userRoot)) {
        std::cerr << "[Debug] createUserFileMapping: user root does not exist " + userRoot << std::endl;
        return false;
    }
    json mapping;
    mapping["username"] = username;
    mapping["root"]     = SecOps::SecurityOps::sha256(username);
    mapping["personal"] = SecOps::SecurityOps::sha256("personal");
    mapping["entries"]  = json::object();  // To track subfolders/files in personal
    //Store public key fingerprint for later verification
    mapping["public_key"] = SecOps::SecurityOps::sha256(userPub);
    //Store the key used for global_mapping.json
    //If user is admin, generate a 32 byte key for global mapping
    if(username == "admin") {
        // generate raw random bytes
        std::string rawkey = SecOps::SecurityOps::generateRandomKey(32);
        // convert to hex string for JSON storage
        std::string key = bytesToHex(rawkey);
        // store the key in the mapping
        mapping["global_mapping_key"] = key;
    }else {
        //For non-admin users, get the key from admin's user_file_mapping.json
        mapping["global_mapping_key"] = UOps::UserOps::loadUserFileMappingPublic("admin", UOps::UserOps::getUser("admin").privateKey)["global_mapping_key"];
    }

    std::string fileNameHash = SecOps::SecurityOps::sha256("user_file_mapping.json");
    std::string filePath = userRoot + "/" + fileNameHash;
    std::string plain = mapping.dump(4);
    std::string encrypted;
    try {
        // Use hybrid encryption: encrypt plain using a random AES key and RSA encrypt that AES key.
        encrypted = SecOps::SecurityOps::hybridEncrypt(plain, userPub);
    } catch(std::exception &e) {
        std::cerr << "[Debug] createUserFileMapping: hybridEncrypt failed: " + std::string(e.what()) << std::endl;
        return false;
    }
    if (!Ops::FileOps::writeFile(filePath, encrypted)) {
        std::cerr << "[Debug] createUserFileMapping: writeFile failed for " + filePath << std::endl;
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
        std::cerr << "[Debug] loadUserFileMappingPublic: file does not exist " + filePath << std::endl;
        return empty;
    }
    std::string encData = Ops::FileOps::readFile(filePath);
    if (encData.empty()) {
        std::cerr << "[Debug] loadUserFileMappingPublic: readFile failed for " + filePath << std::endl;
        return empty;
    }
    std::string decrypted;
    try {
        decrypted = SecOps::SecurityOps::hybridDecrypt(encData, userPriv);
    } catch(std::exception &e) {
        std::cerr << "[Debug] loadUserFileMappingPublic: hybridDecrypt failed: " + std::string(e.what()) << std::endl;
        return empty;
    }
    json j;
    try {
        j = json::parse(decrypted);
    } catch(...) {
        std::cerr << "[Debug] loadUserFileMappingPublic: json parse failed" << std::endl;
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
        Ops::FileOps::appendErrorLog("[Debug] saveUserFileMappingPublic: hybridEncrypt failed: " + std::string(e.what()),
                                      UOps::UserOps::getUser(username));
        return false;
    }
    if (!Ops::FileOps::writeFile(filePath, encrypted)) {
        Ops::FileOps::appendErrorLog("[Debug] saveUserFileMappingPublic: writeFile failed for " + filePath,
                                      UOps::UserOps::getUser(username));
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
            if (username == "admin") {
                std::cerr << "[Debug] createUser: Invalid username: " + username << std::endl;
            } else {
                Ops::FileOps::appendErrorLog("[Debug] Invalid username: " + username,
                                              UOps::UserOps::getUser("admin"));
            }
            return false;
        }
    }
    if (!SecOps::SecurityOps::generateRSAKeyPair(username)) {
        if (username == "admin") {
            std::cerr << "[Debug] createUser: Failed to generate RSA key pair for " + username << std::endl;
        } else {
            Ops::FileOps::appendErrorLog("[Debug] Failed to generate RSA key pair for " + username,
                                          UOps::UserOps::getUser("admin"));
        }
        return false;
    }
    // Read keyfiles.
    std::ifstream privFile(username + "_keyfile.pem");
    if (!privFile) {
        if (username == "admin") {
            std::cerr << "[Debug] createUser: Failed opening " + username + "_keyfile.pem" << std::endl;
        } else {
            Ops::FileOps::appendErrorLog("[Debug] Failed opening " + username + "_keyfile.pem",
                                          UOps::UserOps::getUser("admin"));
        }
        return false;
    }
    std::stringstream privBuf;
    privBuf << privFile.rdbuf();
    std::string userPriv = privBuf.str();
    privFile.close();
    std::ifstream pubFile(username + "_public.pem");
    if (!pubFile) {
        if (username == "admin") {
            std::cerr << "[Debug] createUser: Failed opening " + username + "_public.pem" << std::endl;
        } else {
            Ops::FileOps::appendErrorLog("[Debug] Failed opening " + username + "_public.pem",
                                          UOps::UserOps::getUser("admin"));
        }
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
        if (username == "admin") {
            std::cerr << "[Debug] createUser: Failed to write " + keyfilePath << std::endl;
        } else {
            Ops::FileOps::appendErrorLog("[Debug] Failed to write " + keyfilePath,
                                          UOps::UserOps::getUser("admin"));
        }
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
        if (username == "admin") {
            std::cerr << "[Debug] createUser: Failed to create user_file_mapping for " + username << std::endl;
        } else {
            Ops::FileOps::appendErrorLog("[Debug] Failed to create user_file_mapping for " + username,
                                          UOps::UserOps::getUser("admin"));
        }
        return false;
    }
    
    bool adminFlag = (username == "admin");
    if (adminFlag) {
        if (!UOps::UserOps::updateAdminMapping(username, userPriv, userPub)) {
            if (username == "admin") {
                std::cerr << "[Debug] createUser: Failed to update admin mapping for " + username << std::endl;
            } else {
                Ops::FileOps::appendErrorLog("[Debug] Failed to update admin mapping for " + username,
                                              UOps::UserOps::getUser("admin"));
            }
            return false;
        }
    }
    users[username] = User{username, userPriv, userPub, adminFlag};

    // Update global mapping with emmpty json variable and users
    json globalMapping = json::object();
    if(!UOps::UserOps::saveGlobalMap(globalMapping, users[username])){
        if (username == "admin") {
            std::cerr << "[Debug] createUser: Failed to save global mapping for " + username << std::endl;
        } else {
            Ops::FileOps::appendErrorLog("[Debug] Failed to save global mapping for " + username,
                                          UOps::UserOps::getUser("admin"));
        }
        return false;
    }

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
        std::cerr << "[Debug] login: cannot open keyfile " << keyfilePath << std::endl;
        return "";
    }
    std::string keyData((std::istreambuf_iterator<char>(ifs)),
                        std::istreambuf_iterator<char>());
    ifs.close();
    if (keyData.empty()) {
        std::cerr << "[Debug] login: keyfile is empty " << keyfilePath << std::endl;
        return "";
    }
    std::filesystem::path p(keyfilePath);
    std::string baseKeyfile = p.filename().string();
    size_t pos = baseKeyfile.find("_keyfile.pem");
    if (pos == std::string::npos) {
        std::cerr << "[Debug] login: invalid keyfile name " << baseKeyfile << std::endl;
        return "";
    }
    std::string uname = baseKeyfile.substr(0, pos);
    std::string userRoot = "filesystem/" + SecOps::SecurityOps::sha256(uname);
    if (!std::filesystem::exists(userRoot)) {
        std::cerr << "[Debug] login: user root does not exist for " << uname << std::endl;
        return "";
    }
    // Load the user_file_mapping using hybrid decryption.
    json mapping = loadUserFileMappingPublic(uname, keyData);
    if (mapping.empty()) {
        std::cerr << "[Debug] login: user_file_mapping is empty for " << uname << std::endl;
        return "";
    }
    if (!mapping.contains("username") || mapping["username"] != uname) {
        std::cerr << "[Debug] login: username mismatch in mapping for " << uname << std::endl;
        return "";
    }
    // Read the user's public key.
    std::string pubFilePath = PUBLIC_KEYS_DIR + "/" + uname + "_public.pem";
    std::ifstream pubF(pubFilePath);
    if (!pubF) {
        std::cerr << "[Debug] login: cannot open public key file " << pubFilePath << std::endl;
        return "";
    }
    std::stringstream pubBuf;
    pubBuf << pubF.rdbuf();
    std::string userPub = pubBuf.str();
    pubF.close();
    // Check if the public key fingerprint matches the one in the mapping.
    if (!mapping.contains("public_key") || mapping["public_key"] != SecOps::SecurityOps::sha256(userPub)) {
        std::cerr << "[Debug] login: public key mismatch for " << uname << std::endl;
        return "";
    }
    bool adminFlag = (uname == "admin");
    users[uname] = User{uname, keyData, userPub, adminFlag};
    // if user is admin, open admin_mapping.json and get all users in the list to the in-memory cache
    if (adminFlag) {
        std::string adminMappingFileName = SecOps::SecurityOps::sha256("admin_mapping.json");
        std::string adminMappingPath = "filesystem/" + adminMappingFileName;
        json adminMapping;
        if (Ops::FileOps::fileExists(adminMappingPath)) {
            std::string enc = Ops::FileOps::readFile(adminMappingPath);
            try {
                std::string dec = SecOps::SecurityOps::hybridDecrypt(enc, keyData);
                adminMapping = json::parse(dec);
            } catch (...) {
                adminMapping = json::object();
            }
        }
        for (auto &user : adminMapping.items()) {
            // except for admin itself, add all users to the in-memory cache
            if (user.key() == "admin") continue;
            users[user.key()] = User{user.key(), user.value(), "", false};
        }
    }
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
 * this function is used to update the global_mapping.json file
 * with details of the user, including root, shared, and shared_files
 * the root and shared folders are hashed using sha256
 * the shared_files is a json object that will be updated through j
 * the function will create the global_mapping.json file if it does not exist
 * and will append the user details to it
 * the function will return true if successful, false otherwise
 * to get the details of user, use the getUser function
 * the global_mapping.json file is stored in the filesystem directory
 * the file is named as sha256("global_mapping.json")
 * the file is encrypted/decrypted using the global_mapping_key in the user_file_mapping.json and aesencrypt and aesdecrypt
 * 
 */
json UserOps::loadGlobalMapping(const UOps::User &user) {
    std::string globalMappingFileName = SecOps::SecurityOps::sha256("global_mapping.json");
    std::string globalMappingPath = "filesystem/" + globalMappingFileName;
    json globalMapping;
    globalMapping = json::object();
    // Get the global mapping key from the user_file_mapping.json
    json userFileMapping = loadUserFileMappingPublic(user.username, user.privateKey);
    if (userFileMapping.empty() || !userFileMapping.contains("global_mapping_key")) {
        Ops::FileOps::appendErrorLog("[Debug] saveGlobalMap: global_mapping_key not found in user_file_mapping.json for " + user.username,
                                      UOps::UserOps::getUser(user.username));
        // return empty json object
        return globalMapping;
    }
    std::string globalMappingKey = userFileMapping["global_mapping_key"];
    auto keyBytes = UserOps::hexToBytes(globalMappingKey);
    std::string keyStr(reinterpret_cast<char*>(keyBytes.data()), keyBytes.size());
    // Read the global mapping file.
    // If the file does not exist, create an empty JSON object.
    if (!Ops::FileOps::fileExists(globalMappingPath)) {
        Ops::FileOps::appendErrorLog("[Debug] loadGlobalMapping: global_mapping.json not found",
                                      UOps::UserOps::getUser(user.username));
        
    } else {
        std::string enc = Ops::FileOps::readFile(globalMappingPath);
        try {
            // Decrypt the global mapping file using the global mapping key.
            std::string dec = SecOps::SecurityOps::aesDecrypt(enc, keyStr);
            globalMapping = json::parse(dec);
            return globalMapping;
        } catch (...) {
            Ops::FileOps::appendErrorLog("[Debug] loadGlobalMapping: aesDecrypt failed for " + globalMappingPath,
                                          UOps::UserOps::getUser(user.username));
            return globalMapping;
        }
    }
    return globalMapping;
}
bool UserOps::saveGlobalMap(const json &j, const UOps::User &user) {
    json globalMapping = loadGlobalMapping(user);
    if (globalMapping.empty()) {
        Ops::FileOps::appendErrorLog("[Debug] saveGlobalMap: loadGlobalMapping failed for " + user.username,
                                      UOps::UserOps::getUser(user.username));
    }
    // If the user does not exist in the global mapping, add it.
    if (!globalMapping.contains(user.username)) {
        globalMapping[user.username] = json::object();
        globalMapping[user.username]["root"] = SecOps::SecurityOps::sha256(user.username);
        globalMapping[user.username]["shared"] = SecOps::SecurityOps::sha256("shared");
        globalMapping[user.username]["shared_files"] = json::object();
    }
    // if j is not empty, make the global mapping as j
    if (!j.empty()) {
        globalMapping = j;
    }
    // write the global mapping file
    std::string globalMappingFileName = SecOps::SecurityOps::sha256("global_mapping.json");
    std::string globalMappingPath = "filesystem/" + globalMappingFileName;
    std::string plain = globalMapping.dump(4);
    std::string encrypted;
    // Get the global mapping key from the user_file_mapping.json
    json userFileMapping = loadUserFileMappingPublic(user.username, user.privateKey);
    if (userFileMapping.empty() || !userFileMapping.contains("global_mapping_key")) {
        Ops::FileOps::appendErrorLog("[Debug] saveGlobalMap: global_mapping_key not found in user_file_mapping.json for " + user.username,
                                      UOps::UserOps::getUser(user.username));
        // return empty json object
        return globalMapping;
    }
    std::string globalMappingKey = userFileMapping["global_mapping_key"];
    auto keyBytes = UserOps::hexToBytes(globalMappingKey);
    std::string keyStr(reinterpret_cast<char*>(keyBytes.data()), keyBytes.size());
    // Read the global mapping file.
    try {
        // Encrypt the global mapping file using the global mapping key.
        encrypted = SecOps::SecurityOps::aesEncrypt(plain, keyStr);
    } catch(std::exception &e) {
        Ops::FileOps::appendErrorLog("[Debug] saveGlobalMap: aesEncrypt failed: " + std::string(e.what()),
                                      UOps::UserOps::getUser(user.username));
        return false;
    }
    if (!Ops::FileOps::writeFile(globalMappingPath, encrypted)) {
        Ops::FileOps::appendErrorLog("[Debug] saveGlobalMap: writeFile failed for " + globalMappingPath,
                                      UOps::UserOps::getUser(user.username));
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
        Ops::FileOps::appendErrorLog("[Debug] updateAdminMapping: failed to open admin public key file",
                                      UOps::UserOps::getUser("admin"));
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
        Ops::FileOps::appendErrorLog("[Debug] updateAdminMapping: hybridEncrypt failed: " + std::string(e.what()),
                                      UOps::UserOps::getUser("admin"));
        return false;
    }
    bool success = Ops::FileOps::writeFile(adminMappingPath, encrypted);
    if (!success) {
        Ops::FileOps::appendErrorLog("[Debug] updateAdminMapping: writeFile failed for " + adminMappingPath,
                                      UOps::UserOps::getUser("admin"));
        return false;
    }
    return success;
}

} // namespace UOps