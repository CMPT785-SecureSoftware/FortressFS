#ifndef USER_OPS_H
#define USER_OPS_H

#include <string>
#include <unordered_map>

namespace UOps {

    /**
     * User represents a system user.
     * - username: Plaintext username.
     * - privateKey: The decrypted private key loaded from the keyfile.
     * - publicKey: The corresponding public key loaded from disk.
     * - isAdmin: Flag indicating whether the user is an administrator.
     */
    struct User {
        std::string username;
        std::string privateKey;
        std::string publicKey;
        bool isAdmin;
    };

    /**
     * UserOps provides functionality to create and log in users, and to manage
     * global mappings. It also caches the current user.
     */
    class UserOps {
    public:
        // Creates a new user (used by admin) and sets up the per-user mapping file.
        static bool createUser(const std::string &username);

        // Logs in a user by decrypting the per-user mapping file.
        static std::string login(const std::string &keyfilePath);

        // Returns the in-memory user record.
        static User getUser(const std::string &username);

        // Checks if a user is already in the in-memory cache.
        static bool userExists(const std::string &username);

        // Updates the global mapping file (global_mapping.json) with the user's base directory info.
        static bool mapUser(const std::string &username, const std::string &publicKey);

        // Updates the admin mapping (admin_mapping.json) with new user info.
        // admin_mapping.json is stored in FILESYSTEM_DIR, encrypted using admin's private key.
        static bool updateAdminMapping(const std::string &username, const std::string &userPrivateKey, const std::string &adminPrivateKey);

        // In-memory cache of the user (only one user exists per session).
        static std::unordered_map<std::string, User> users;
    };
}

#endif