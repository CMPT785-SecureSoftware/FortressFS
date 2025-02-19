#include "UserOps.h"
#include "SecurityOps.h"
#include "FileOps.h"

#include <fstream>
#include <sstream>
#include <iostream>
#include <unordered_map>

namespace UOps {
    std::unordered_map<std::string, User> UserOps::users;

    bool UserOps::createUser(const std::string& username, bool admin) {
        if (userExists(username)) return false;

        // generateRSAKeyPair now uses the EVP approach
        if (!SecOps::SecurityOps::generateRSAKeyPair(username)) {
            return false;
        }

        // Read newly created keys from disk
        std::ifstream privFile(username + "_private.pem");
        std::stringstream privBuf;
        privBuf << privFile.rdbuf();
        std::string privateKey = privBuf.str();

        std::ifstream pubFile(username + "_public.pem");
        std::stringstream pubBuf;
        pubBuf << pubFile.rdbuf();
        std::string publicKey = pubBuf.str();

        User u {username, privateKey, publicKey, admin};
        users[username] = u;
        return true;
    }

    bool UserOps::addUserFromKeys(const std::string& username,
                                  const std::string& privateKey,
                                  const std::string& publicKey,
                                  bool admin) {
        if (userExists(username)) return false;
        User u {username, privateKey, publicKey, admin};
        users[username] = u;
        return true;
    }

    bool UserOps::userExists(const std::string& username) {
        return (users.find(username) != users.end());
    }

    User UserOps::getUser(const std::string& username) {
        if (userExists(username)) {
            return users[username];
        }
        return User{"", "", "", false};
    }

    std::string UserOps::login(const std::string& privateKeyPath) {
        // Read private key from file
        std::ifstream in(privateKeyPath);
        if (!in) {
            std::cerr << "Could not open key file.\n";
            return "";
        }
        std::stringstream buf;
        buf << in.rdbuf();
        std::string privateKey = buf.str();

        // Attempt match with known users
        for (auto& [uname, user] : users) {
            if (user.privateKey == privateKey) {
                return uname; // Successful login
            }
        }
        return "";
    }
}