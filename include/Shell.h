#ifndef SHELL_H
#define SHELL_H

#include <string>

namespace Shell {
<<<<<<< HEAD

    /**
     * InteractiveShell handles the CLI for a user (or admin),
     * supporting commands: cd, pwd, ls, cat, share, mkdir, mkfile, adduser, exit, help.
     * It enforces restrictions for normal users and admin roles.
     */
    class InteractiveShell {
    public:
        // Constructor: pass the logged-in username.
        InteractiveShell(const std::string &username);

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

=======
    // InteractiveShell implements the command-line interface for the file system.
    // Supported commands include: cd, pwd, ls, cat, share, mkdir, mkfile, exit, and adduser (admin-only).
    class InteractiveShell {
    public:
        // Constructor: takes the logged-in username.
        InteractiveShell(const std::string &username);

        // Starts the shell loop.
        void start();

    private:
        std::string currentUser;  // Logged-in user.
        std::string currentDir;   // Virtual current directory (starting at "/").

        // Resolves a virtual path (e.g., /personal/test.txt) to an absolute path within FILESYSTEM_DIR/<user>.
        std::string resolvePath(const std::string &vpath);

        // Normalizes a path to handle "." and "..".
        std::string normalizePath(const std::string &path);

        // Command handler methods.
        void handle_cd(const std::string &arg);          // Change directory.
        void handle_pwd();                                 // Print working directory.
        void handle_ls();                                  // List directory contents.
        void handle_cat(const std::string &filename);      // Display file contents (decrypted).
        void handle_share(const std::string &args);        // Share a file with another user.
        void handle_mkdir(const std::string &dirname);     // Create a directory.
        void handle_mkfile(const std::string &args);       // Create/update a file.
        void handle_adduser(const std::string &username);  // Admin-only: create a new user.

        // Displays help information.
        void showHelp();
    };
>>>>>>> 8874a9cf4754fcd8b285cc15a9acf5c728818402
}

#endif