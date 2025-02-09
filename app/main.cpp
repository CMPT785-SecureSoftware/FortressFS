#include <iostream>
#include "UserOps.h"
#include "Shell.h"
#include "FileOps.h"
#include <filesystem>
#include <fstream>
#include "SecurityOps.h"

static const std::string FORTRESS_DIR = "Fortressfs_Folder";
static const std::string ENCRYPTED_KEYS_DIR = FORTRESS_DIR + "/EncryptedKeys";
static const std::string ADMIN_KEYFILE = "admin_keyfile";

// Initialize the fortress folder structure:
// Create Fortressfs_Folder and EncryptedKeys.
// If the admin keyfile does not exist, create it and generate admin’s directories.
static void initFortress() {
    if (!std::filesystem::exists(FORTRESS_DIR))
        std::filesystem::create_directories(FORTRESS_DIR);
    if (!std::filesystem::exists(ENCRYPTED_KEYS_DIR))
        std::filesystem::create_directories(ENCRYPTED_KEYS_DIR);
    std::string adminPath = ENCRYPTED_KEYS_DIR + "/" + ADMIN_KEYFILE;
    if (!std::filesystem::exists(adminPath)) {
        // For demonstration, we generate admin's key pair and store the private key encrypted with itself.
        // In a real system, admin_keyfile should be generated securely.
        if (!SecOps::SecurityOps::generateRSAKeyPair("admin")) {
            std::cerr << "Failed to generate admin key pair\n";
            exit(1);
        }
        // Read admin private key.
        std::ifstream ifs("admin_private.pem");
        std::stringstream ss;
        ss << ifs.rdbuf();
        std::string adminPriv = ss.str();
        // For simplicity, we use a fixed symmetric key (ADMIN_SYMMETRIC_KEY in UserOps)
        // to encrypt admin's private key. (In practice, this key must be derived securely.)
        std::string encryptedAdminKey = SecOps::SecurityOps::aesEncrypt(adminPriv, "0123456789abcdef0123456789abcdef");
        // Write admin keyfile to EncryptedKeys.
        std::ofstream ofs(adminPath, std::ios::binary);
        ofs << encryptedAdminKey;
        ofs.close();
        // Create admin directories.
        std::filesystem::create_directories(FORTRESS_DIR + "/admin/personal");
        std::filesystem::create_directories(FORTRESS_DIR + "/admin/shared");
        // Add admin to in-memory user table.
        UOps::UserOps::users["admin"] = UOps::UserOps::User{"admin", adminPriv, "", true};
        std::cout << "Admin user created. Please secure the admin keyfile.\n";
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cout << "Usage: ./fileserver <keyfile_name>\n";
        return 1;
    }
    initFortress();

    // Attempt login using the provided keyfile.
    std::string keyfileName = argv[1];
    std::string user = UOps::UserOps::UserOps::login(keyfileName);
    if (user.empty()) {
        std::cout << "Invalid keyfile\n";
        return 1;
    }
    std::cout << "Logged in as " << user << "\n";

    // Ensure the user's folder exists.
    std::string userDir = FORTRESS_DIR + "/" + user;
    if (!std::filesystem::exists(userDir)) {
        std::filesystem::create_directories(userDir + "/personal");
        std::filesystem::create_directories(userDir + "/shared");
    }

    // Start interactive shell.
    Shell::InteractiveShell shell(user);
    shell.start();

    return 0;
}