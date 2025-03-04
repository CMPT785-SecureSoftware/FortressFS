#ifndef SHELL_H
#define SHELL_H

#include <string>

namespace Shell {

    /**
     * InteractiveShell handles the CLI for a user (or admin),
     * supporting commands: cd, pwd, ls, cat, share, mkdir, mkfile, adduser, exit, help.
     * It enforces restrictions for normal users and admin roles.
     */
    class InteractiveShell {
    public:
        // Constructor: pass the logged-in username.
        explicit InteractiveShell(const std::string &username);

        // Begin the interactive loop
        void start();

    private:
        std::string currentUser;  // e.g. "admin", "jeril", ...
        std::string currentDir;   // e.g. "/", "/personal", ...
        bool isAdminFSMode;       // admin "filesystem" view
        std::string viewedUser;   // if admin is viewing user X

        // Convert a virtual path like "/shared/docs" to a hashed on-disk path
        std::string resolvePath(const std::string &vpath);

        // Normalize path by interpreting "." and ".."
        std::string normalizePath(const std::string &path);

        // Command handlers
        void handle_cd(const std::string &arg);
        void handle_pwd();
        void handle_ls();
        void handle_cat(const std::string &filename);
        void handle_share(const std::string &args);
        void handle_mkdir(const std::string &dirname);
        void handle_mkfile(const std::string &args);
        void handle_adduser(const std::string &username);

        // Show commands depending on user role and directory
        void showHelp();
    };

}

#endif
