#ifndef USER_OPS_H
#define USER_OPS_H

#include <string>
#include <unordered_map>

/**
 * The UOps namespace encapsulates operations related to user management.
 */
namespace UOps {

    /**
     * User structure represents a user with a username, private key,
     * public key, and a flag indicating if the user is an administrator.
     */
    struct User {
        std::string username;
        std::string privateKey;  // Decrypted private key loaded from keyfile.
        std::string publicKey;   // Public key loaded from disk.
        bool isAdmin;
    };

    /**
     * UserOps provides functionality to create users, log in users, and manage global mappings.
     * It also caches the current user in memory.
     */
    class UserOps {
    public:
        // Creates a new user (used by admin) and sets up the per-user mapping file.
        static bool createUser(const std::string &username);

        // Logs in a user by reading and decrypting the per-user mapping file.
        static std::string login(const std::string &keyfilePath);

        // Returns the User record from the in-memory cache.
        static User getUser(const std::string &username);

        // Checks if a user exists in the in-memory cache.
        static bool userExists(const std::string &username);

        // Updates the global mapping file (global_mapping.json) with the user's base directory info.
        static bool mapUser(const std::string &username, const std::string &publicKey);

        // Updates the admin mapping file (admin_mapping.json) with the new user's private key.
        // This mapping is stored in FILESYSTEM_DIR and is encrypted using admin's private key.
        static bool updateAdminMapping(const std::string &username, const std::string &userPrivateKey, const std::string &adminPrivateKey);

        // In-memory cache for the user (only one user exists per session).
        static std::unordered_map<std::string, User> users;
    };
}

#endif