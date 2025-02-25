#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include "UserOps.h"
#include "Shell.h"
#include "FileOps.h"
#include "SecurityOps.h"

// Constants for folder structure.
static const std::string FILESYSTEM_DIR = "filesystem";              // The encrypted filesystem folder
static const std::string ENCRYPTED_KEYS_DIR = FILESYSTEM_DIR + "/EncryptedKeys"; // Where encrypted user keyfiles are stored
static const std::string ADMIN_KEYS_DIR = "admin_keys";                // Where admin keys are stored in plaintext
static const std::string PUBLIC_KEYS_DIR = "public_keys";              // Where public keys are stored (outside the filesystem)
static const std::string ADMIN_KEYFILE = "admin_keyfile";              // Admin private key filename in ADMIN_KEYS_DIR

// initFortress() creates the required folder structure.
// If the admin keyfile does not exist in ADMIN_KEYS_DIR, it generates the admin keypair,
// moves the admin private key to ADMIN_KEYS_DIR, moves the public key to PUBLIC_KEYS_DIR,
// creates the filesystem structure for admin, and then exits.
static void initFortress() {
    // Create the main filesystem folder.
    if (!std::filesystem::exists(FILESYSTEM_DIR))
        std::filesystem::create_directories(FILESYSTEM_DIR);
    
    // Create the EncryptedKeys folder for user keyfiles.
    if (!std::filesystem::exists(ENCRYPTED_KEYS_DIR))
        std::filesystem::create_directories(ENCRYPTED_KEYS_DIR);
    
    // Create the admin_keys folder.
    if (!std::filesystem::exists(ADMIN_KEYS_DIR))
        std::filesystem::create_directories(ADMIN_KEYS_DIR);
    
    // Create the public_keys folder.
    if (!std::filesystem::exists(PUBLIC_KEYS_DIR))
        std::filesystem::create_directories(PUBLIC_KEYS_DIR);
    
    // Path for the admin keyfile in admin_keys.
    std::string adminPath = ADMIN_KEYS_DIR + "/" + ADMIN_KEYFILE;
    
    // If admin keyfile does not exist, create it.
    if (!std::filesystem::exists(adminPath)) {
        // Generate admin's RSA key pair.
        if (!SecOps::SecurityOps::generateRSAKeyPair("admin")) {
            std::cerr << "Failed to generate admin key pair\n";
            exit(1);
        }
        // Read the generated admin private key (from "admin_private.pem").
        std::ifstream ifs("admin_private.pem");
        std::stringstream ss;
        ss << ifs.rdbuf();
        std::string adminPriv = ss.str();
        // Write admin's private key (plaintext) to the admin_keys folder.
        std::ofstream ofs(adminPath, std::ios::binary);
        ofs << adminPriv;
        ofs.close();
        // Move the admin public key to the public_keys folder.
        std::string pubSrc = "admin_public.pem";
        std::string pubDst = PUBLIC_KEYS_DIR + "/admin_public.pem";
        std::filesystem::rename(pubSrc, pubDst);
        // Create admin's filesystem folder (inside FILESYSTEM_DIR).
        std::filesystem::create_directories(FILESYSTEM_DIR + "/admin/personal");
        std::filesystem::create_directories(FILESYSTEM_DIR + "/admin/shared");
        // Add admin to the in-memory user table.
        UOps::UserOps::users["admin"] = UOps::User{"admin", adminPriv, "", true};
        std::cout << "Admin keys created and stored in " << adminPath << "\n";
        std::cout << "Admin public key stored in " << pubDst << "\n";
        std::cout << "Please secure your admin keyfile. Exiting now. (Re-run the program with a valid keyfile.)\n";
        exit(0);
    }
}

int main(int argc, char **argv) {
    // First, initialize the fortress folder structure and admin keys.
    initFortress();

    // The program is expected to be run as: ./fileserver <keyfile_name>
    if (argc < 2) {
        std::cout << "Usage: ./fileserver <keyfile_name>\n";
        return 1;
    }

    // Attempt to log in using the provided keyfile.
    std::string keyfileName = argv[1];
    std::string user = UOps::UserOps::login(keyfileName);
    if (user.empty()) {
        std::cout << "Invalid keyfile\n";
        return 1;
    }
    std::cout << "Logged in as " << user << "\n";

    // Ensure the user's folder exists within the filesystem.
    std::string userDir = FILESYSTEM_DIR + "/" + user;
    if (!std::filesystem::exists(userDir)) {
        std::filesystem::create_directories(userDir + "/personal");
        std::filesystem::create_directories(userDir + "/shared");
    }

    // Start the interactive shell.
    Shell::InteractiveShell shell(user);
    shell.start();

    return 0;
}