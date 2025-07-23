#include <string>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <cstdio>
#include <cstdlib>
#include <limits.h>
#include <unistd.h>

#include "utils/string.h"

// Enable file access safety by default.
// Define FILE_READ_UNSAFE to disable path restrictions.
#ifndef FILE_READ_UNSAFE
#define FILE_READ_SAFE
#pragma message("FILE_READ_SAFE is enabled: access is limited to ./config and ./rules")
#else
#pragma message("FILE_READ_UNSAFE is enabled: access is NOT restricted")
#endif

// Check if a given path is within ./config or ./rules (only when FILE_READ_SAFE is defined)
static bool isInScope(const std::string& path)
{
#ifdef FILE_READ_SAFE
    char real_target[PATH_MAX];
    if (!realpath(path.c_str(), real_target)) {
        return false;
    }

    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        return false;
    }

    std::string allowed1 = std::string(cwd) + "/config";
    std::string allowed2 = std::string(cwd) + "/rules";

    auto matchPath = [](const char* target, const std::string& base) {
        size_t len = base.length();
        return strncmp(target, base.c_str(), len) == 0 &&
               (target[len] == '\0' || target[len] == '/');
    };

    return matchPath(real_target, allowed1) || matchPath(real_target, allowed2);
#else
#ifdef _WIN32
    if (path.find(":\\") != path.npos || path.find("..") != path.npos)
        return false;
#else
    if (startsWith(path, "/") || path.find("..") != path.npos)
        return false;
#endif
    return true;
#endif
}

// Read the content of a file as string
std::string fileGet(const std::string& path, bool scope_limit)
{
    if (scope_limit && !isInScope(path))
        return "";

    std::ifstream infile(path, std::ios::binary);
    if (!infile)
        return "";

    std::ostringstream buffer;
    buffer << infile.rdbuf();
    return buffer.str();
}

// Check if a file exists and is a regular file
bool fileExist(const std::string& path, bool scope_limit)
{
    if (scope_limit && !isInScope(path))
        return false;

    struct stat st;
    return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

// Copy contents from one file to another
bool fileCopy(const std::string &source, const std::string &dest)
{
    if ((!isInScope(source) || !isInScope(dest)))
        return false;

    std::ifstream infile(source, std::ios::binary);
    if (!infile)
        return false;

    std::ofstream outfile(dest, std::ios::binary);
    if (!outfile)
        return false;

    try {
        outfile << infile.rdbuf();
    } catch (...) {
        return false;
    }

    return true;
}

// Write content to a file (overwrite or append mode)
int fileWrite(const std::string &path, const std::string &content, bool overwrite)
{
    if ( !isInScope(path))
        return -1;

    std::ios_base::openmode mode = std::ios::binary | (overwrite ? std::ios::trunc : std::ios::app);
    std::ofstream outfile(path, mode);
    if (!outfile)
        return -1;

    outfile.write(content.c_str(), content.size());
    return outfile.good() ? 0 : -2;
}
