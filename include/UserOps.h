#ifndef USER_OPS_H
#define USER_OPS_H

#include <string>
#include <unordered_map>

namespace UOps {

    /**
     * User represents a system user with a username, a decrypted private key,
     * a public key, and a flag indicating if the user is an administrator.
     */
    struct User {
        std::string username;
        std::string privateKey;  // Decrypted private key loaded from the keyfile.
        std::string publicKey;   // Public key loaded from disk.
        bool isAdmin;
    };

    /**
     * UserOps provides functionality for creating and logging in users,
     * as well as updating global and admin mappings.
     */
    class UserOps {
    public:
        // Creates a new user (used by admin) and sets up the per-user mapping file.
        static bool createUser(const std::string &username);

        // Logs in a user by decrypting the per-user mapping file.
        static std::string login(const std::string &keyfilePath);

        // Returns the User record from the in-memory cache.
        static User getUser(const std::string &username);

        // Checks whether a user exists in the in-memory cache.
        static bool userExists(const std::string &username);

        // Updates the global mapping file (global_mapping.json) with the user's base directory info.
        static bool mapUser(const std::string &username, const std::string &publicKey);

        // Updates the admin mapping file (admin_mapping.json) with the new user's private key.
        // This file is stored in FILESYSTEM_DIR and is encrypted using admin's private key.
        static bool updateAdminMapping(const std::string &username, const std::string &userPrivateKey, const std::string &adminPrivateKey);

        // In-memory cache for users (only one user per session is used).
        static std::unordered_map<std::string, User> users;
    };
}

#endif