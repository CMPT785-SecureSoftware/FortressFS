#include "UserOps.h"
#include "SecurityOps.h"
#include "FileOps.h"

#include <fstream>
#include <sstream>
#include <iostream>
#include <unordered_map>
#include <ctime>

namespace UOps {
    std::unordered_map<std::string, User> UserOps::users;

    // Utility function to get the current timestamp
    std::string getCurrentTimestamp() {
        std::time_t now = std::time(nullptr);
        char buf[20];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
        return std::string(buf);
    }

    bool UserOps::createUser(const std::string& username, bool admin) {
        if (userExists(username)) return false;

        // generateRSAKeyPair now uses the EVP approach
        if (!SecOps::SecurityOps::generateRSAKeyPair(username)) {
            return false;
        }

        // Read newly created keys from disk
        std::ifstream privFile(username + "_private.pem");
        if (!privFile) {
            std::cerr << "[" << getCurrentTimestamp() << "] Error: Could not read private key file for " << username << "\n";
            return false;
        }
        std::stringstream privBuf;
        privBuf << privFile.rdbuf();
        std::string privateKey = privBuf.str();

        std::ifstream pubFile(username + "_public.pem");
        if (!pubFile) {
            std::cerr << "[" << getCurrentTimestamp() << "] Error: Could not read public key file for " << username << "\n";
            return false;
        }
        std::stringstream pubBuf;
        pubBuf << pubFile.rdbuf();
        std::string publicKey = pubBuf.str();

        User u {username, privateKey, publicKey, admin};
        users[username] = u;
        std::cout << "[" << getCurrentTimestamp() << "] User created: " << username << "\n";
        return true;
    }

    bool UserOps::addUserFromKeys(const std::string& username,
                                  const std::string& privateKey,
                                  const std::string& publicKey,
                                  bool admin) {
        if (userExists(username)) return false;
        User u {username, privateKey, publicKey, admin};
        users[username] = u;
        std::cout << "[" << getCurrentTimestamp() << "] User added from keys: " << username << "\n";
        return true;
    }

    bool UserOps::userExists(const std::string& username) {
        return (users.find(username) != users.end());
    }

    User UserOps::getUser(const std::string& username) {
        if (userExists(username)) {
            return users[username];
        }
        std::cerr << "[" << getCurrentTimestamp() << "] Warning: Attempted to retrieve non-existent user: " << username << "\n";
        return User{"", "", "", false};
    }

    std::string UserOps::login(const std::string& privateKeyPath) {
        // Read private key from file
        std::ifstream in(privateKeyPath);
        if (!in) {
            std::cerr << "[" << getCurrentTimestamp() << "] Error: Could not open key file at " << privateKeyPath << "\n";
            return "";
        }
        std::stringstream buf;
        buf << in.rdbuf();
        std::string privateKey = buf.str();

        // Attempt match with known users
        for (auto& [uname, user] : users) {
            if (user.privateKey == privateKey) {
                std::cout << "[" << getCurrentTimestamp() << "] Login successful for user: " << uname << "\n";
                return uname; // Successful login
            }
        }
        std::cerr << "[" << getCurrentTimestamp() << "] Error: Invalid private key provided.\n";
        return "";
    }
}