#ifndef USER_OPS_H
#define USER_OPS_H

#include <string>
#include <unordered_map>

/**
 * Namespace UOps encapsulates operations related to user management,
 * such as creating users, logging in, and updating mappings.
 */
namespace UOps {

    struct User {
        std::string username;
        std::string privateKey;
        std::string publicKey;
        bool isAdmin;
    };

    class UserOps {
    public:
        // createUser: generates keys, moves them, updates global mapping, etc.
        static bool createUser(const std::string &username);

        // login: logs in using <username>_keyfile.pem content, decrypts mapping, verifies username.
        static std::string login(const std::string &keyfilePath);

        // getUser: returns the user from in-memory cache.
        static User getUser(const std::string &username);

        // userExists: checks if user is in the in-memory cache.
        static bool userExists(const std::string &username);

        // mapUser: updates global_mapping.json with user root, shared, etc.
        static bool mapUser(const std::string &username, const std::string &publicKey);

        // updateAdminMapping: updates admin_mapping.json with user private key, encrypted with admin's private key.
        static bool updateAdminMapping(const std::string &username, const std::string &userPrivateKey, const std::string &adminPrivateKey);

        // The in-memory cache of users. Key is username.
        static std::unordered_map<std::string, User> users;

    private:
        /**
         * createUserFileMapping:
         * Creates a JSON describing the user_file_mapping (root hash, personal hash, subfolders, etc.),
         * encrypts it with the user's publicKey, and writes it to the user's root folder. 
         * This ensures that a user_file_mapping.json is present in an encrypted form.
         */
        static bool createUserFileMapping(const std::string &username, const std::string &userPub);

        /**
         * loadUserFileMapping:
         * Reads the encrypted user_file_mapping from the user's root, 
         * decrypts with userPriv, and returns the parsed JSON. 
         * If anything fails, returns an empty object.
         */
        static nlohmann::json loadUserFileMapping(const std::string &username, const std::string &userPriv);
    };
}

#endif