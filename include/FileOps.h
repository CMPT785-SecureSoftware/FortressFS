#ifndef FILE_OPS_H
#define FILE_OPS_H

#include <string>

/**
 * Namespace Ops encapsulates basic file and directory operations.
 */
namespace Ops {

    /**
     * FileOps provides static methods for performing common file operations,
     * such as reading, writing, and checking for the existence of files or directories,
     * as well as creating directories.
     */
    class FileOps {
    public:
        /**
         * writeFile:
         * Writes the given data (in binary mode) to the specified file path.
         * @param path: The path to the file where data will be written.
         * @param data: The content to write to the file.
         * @return true if writing succeeds; otherwise, false.
         */
        static bool writeFile(const std::string &path, const std::string &data);

        /**
         * readFile:
         * Reads the entire content of the file specified by path.
         * @param path: The path to the file.
         * @return The file content as a string; returns an empty string if the file cannot be opened.
         */
        static std::string readFile(const std::string &path);

        /**
         * makeDirectory:
         * Creates a directory at the specified path, including all necessary parent directories.
         * @param path: The directory path to create.
         * @return true if the directory is successfully created; otherwise, false.
         */
        static bool makeDirectory(const std::string &path);

        /**
         * fileExists:
         * Checks whether a file exists at the given path.
         * @param path: The file path.
         * @return true if the file exists and is a regular file; otherwise, false.
         */
        static bool fileExists(const std::string &path);

        /**
         * directoryExists:
         * Checks whether a directory exists at the given path.
         * @param path: The directory path.
         * @return true if the directory exists; otherwise, false.
         */
        static bool directoryExists(const std::string &path);
    };

} // namespace Ops

#endif