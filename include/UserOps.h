#ifndef USER_OPS_H
#define USER_OPS_H

#include <string>
#include <unordered_map>
#include <nlohmann/json.hpp>

// Create an alias for convenience.
namespace UOps {
    using json = nlohmann::json;

    /**
     * User structure contains:
     *  - username
     *  - privateKey (the actual RSA private key content)
     *  - publicKey
     *  - isAdmin (true for admin)
     */
    struct User {
        std::string username;
        std::string privateKey;
        std::string publicKey;
        bool isAdmin;
    };

    /**
     * UserOps provides functions for user management:
     *  - createUser: Generates key pairs, creates directory structure, and stores mapping.
     *  - login: Logs in a user using a keyfile.
     *  - getUser / userExists: Manage the in-memory user cache.
     *  - mapUser / updateAdminMapping: Update global mapping and admin mapping.
     *
     * Additionally, it provides public helper functions to load and save the encrypted
     * user_file_mapping.json.
     */
    class UserOps {
    public:
        // createUser: generates keys, moves them, updates global mapping, etc.
        static bool createUser(const std::string &username);

        // login: logs in using <username>_keyfile.pem content, decrypts user_file_mapping, verifies username.
        static std::string login(const std::string &keyfilePath);

        // getUser: returns the user from in-memory cache.
        static User getUser(const std::string &username);

        // userExists: checks if user is in the in-memory cache.
        static bool userExists(const std::string &username);

        // mapUser: updates global_mapping.json with user root, shared, etc.
        static bool mapUser(const std::string &username, const std::string &publicKey);

        // updateAdminMapping: updates admin_mapping.json with user private key, encrypted with admin's private key.
        static bool updateAdminMapping(const std::string &username, const std::string &userPrivateKey, const std::string &adminPrivateKey);

        // Public helper to load the user's encrypted file mapping.
        static json loadUserFileMappingPublic(const std::string &username, const std::string &userPriv);

        // Public helper to save the user's encrypted file mapping.
        static bool saveUserFileMappingPublic(const std::string &username, const std::string &userPub, const json &mapping);

        // In-memory cache of users.
        static std::unordered_map<std::string, User> users;

    private:
        /**
         * createUserFileMapping:
         * Creates a JSON describing the user's file mapping (e.g., root folder, personal folder, etc.),
         * encrypts it with a hybrid approach (AES encryption using a random key, which is then RSA-encrypted
         * using the user's public key), and writes it to the user's root folder.
         * The file is named as sha256("user_file_mapping.json") under filesystem/<sha256(username)>.
         */
        static bool createUserFileMapping(const std::string &username, const std::string &userPub);
    };
}

#endif