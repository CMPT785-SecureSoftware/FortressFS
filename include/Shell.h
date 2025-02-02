#ifndef SHELL_H
#define SHELL_H

#include <string>

namespace Shell
{
    // Interactive shell with command parsing
    class InteractiveShell {
    public:
        InteractiveShell(const std::string& username);
        void start();

    private:
        std::string currentUser;
        std::string currentDir;  // We'll store a "home" path for the user

        // Command handlers
        void handleMkdir(const std::string& dirName);
        void handleCreateFile(const std::string& fileName, const std::string& content);
        void handleReadFile(const std::string& fileName);
        void handleShare(const std::string& fileName, const std::string& targetUser);

        void showHelp();
    };
}

#endif