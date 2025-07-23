#include <string>
#include <fstream>
#include <sstream>
#include <sys/stat.h>  // For stat, S_ISREG
#include <cstdio>      // For std::FILE
#include <cstdlib>     // For realpath (POSIX)
#include <limits.h>    // For PATH_MAX
#include <unistd.h>    // For getcwd (POSIX)
#include <algorithm>   // For std::transform
#include <cctype>      // For std::tolower

#include "utils/string.h"  // Assuming startsWith is defined here

#ifdef _WIN32
    #include <windows.h>
    #include <shlwapi.h>      // For PathCanonicalize
    #pragma comment(lib, "shlwapi.lib")  // Link automatically
#endif

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
    #ifdef _WIN32
        char real_target_buf[MAX_PATH];
        if (GetFullPathNameA(path.c_str(), MAX_PATH, real_target_buf, nullptr) == 0)
            return false;

        std::string s_real_target = real_target_buf;

        char cwd_buf[MAX_PATH];
        if (GetCurrentDirectoryA(MAX_PATH, cwd_buf) == 0)
            return false;

        std::string s_cwd = cwd_buf;

        std::transform(s_real_target.begin(), s_real_target.end(), s_real_target.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        std::transform(s_cwd.begin(), s_cwd.end(), s_cwd.begin(),
                       [](unsigned char c){ return std::tolower(c); });

        for (char& c : s_real_target) if (c == '\\') c = '/';
        for (char& c : s_cwd) if (c == '\\') c = '/';

        std::string allowed1 = s_cwd + "/config";
        std::string allowed2 = s_cwd + "/rules";

        auto matchPath = [](const std::string& target, const std::string& base) {
            if (target.length() < base.length()) return false;
            if (target.compare(0, base.length(), base) == 0) {
                char next = target.length() > base.length() ? target[base.length()] : '\0';
                return next == '\0' || next == '/';
            }
            return false;
        };

        return matchPath(s_real_target, allowed1) || matchPath(s_real_target, allowed2);

    #else  // POSIX
        char real_target[PATH_MAX];
        if (!realpath(path.c_str(), real_target))
            return false;

        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof(cwd)))
            return false;

        std::string allowed1 = std::string(cwd) + "/config";
        std::string allowed2 = std::string(cwd) + "/rules";

        auto matchPath = [](const char* target, const std::string& base) {
            size_t len = base.length();
            return strncmp(target, base.c_str(), len) == 0 &&
                   (target[len] == '\0' || target[len] == '/');
        };

        return matchPath(real_target, allowed1) || matchPath(real_target, allowed2);
    #endif

#else  // FILE_READ_UNSAFE
    #ifdef _WIN32
        if (path.find(":\\") != std::string::npos || path.find("..") != std::string::npos)
            return false;
    #else
        if (startsWith(path, "/") || path.find("..") != std::string::npos)
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
    if (!isInScope(source) || !isInScope(dest))
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
    if (!isInScope(path))
        return -1;

    std::ios_base::openmode mode = std::ios::binary | (overwrite ? std::ios::trunc : std::ios::app);
    std::ofstream outfile(path, mode);
    if (!outfile)
        return -1;

    outfile.write(content.c_str(), content.size());
    return outfile.good() ? 0 : -2;
}
