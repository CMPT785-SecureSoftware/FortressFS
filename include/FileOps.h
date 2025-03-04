#ifndef FILE_OPS_H
#define FILE_OPS_H

#include <string>

/**
 * Namespace Ops encapsulates basic file and directory I/O operations,
 * such as reading/writing files and creating/checking directories.
 */
namespace Ops {

    class FileOps {
    public:
        /**
         * writeFile:
         * Writes data (in binary mode) to the specified path.
         * @param path File path.
         * @param data Content to write.
         * @return true if successful, false otherwise.
         */
        static bool writeFile(const std::string &path, const std::string &data);

        /**
         * readFile:
         * Reads the entire file content from path.
         * @param path File path.
         * @return File content. Empty if not found or error.
         */
        static std::string readFile(const std::string &path);

        /**
         * makeDirectory:
         * Creates a directory at path (including parents).
         * @param path Directory path.
         * @return true if successful, false otherwise.
         */
        static bool makeDirectory(const std::string &path);

        /**
         * fileExists:
         * Checks if a path exists and is a regular file.
         */
        static bool fileExists(const std::string &path);

        /**
         * directoryExists:
         * Checks if path exists and is a directory.
         */
        static bool directoryExists(const std::string &path);

        /**
         * appendErrorLog:
         * Appends the provided 'message' string to "error.log" for internal debugging.
         * This ensures that user-facing messages are not displayed.
         */
        static void appendErrorLog(const std::string &message);
    };

} // namespace Ops

#endif
