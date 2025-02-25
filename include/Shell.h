#ifndef SHELL_H
#define SHELL_H

#include <string>

namespace Shell {

    class InteractiveShell {
    public:
        InteractiveShell(const std::string &username);
        void start();

    private:
        std::string currentUser;  // logged in user (e.g., "admin" or a normal user)
        std::string currentDir;   // virtual current directory, starting at "/" (user root)

        // Helper to resolve a virtual path (e.g., /personal/test.txt) into an absolute path in Fortressfs_Folder.
        std::string resolvePath(const std::string &vpath);

        // Normalize path (handle . and ..)
        std::string normalizePath(const std::string &path);

        // Command handlers:
        void handle_cd(const std::string &arg);
        void handle_pwd();
        void handle_ls();
        void handle_cat(const std::string &filename);
        void handle_share(const std::string &args);
        void handle_mkdir(const std::string &dirname);
        void handle_mkfile(const std::string &args);
        void handle_adduser(const std::string &username);  // Admin-only: create a new user.
        void handle_exportkey(const std::string &username); // Admin-only: export a user's key as a PEM file.

        void showHelp();
    };

}

#endif