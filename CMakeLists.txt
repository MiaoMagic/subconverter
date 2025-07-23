cmake_minimum_required(VERSION 3.5)
project(subconverter LANGUAGES CXX)

set(BUILD_TARGET_NAME ${PROJECT_NAME})
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
include_directories("${CMAKE_SOURCE_DIR}/include/")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(NOT MSVC)
    add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-unused-result)
else()
    add_compile_options(/W4)
endif()

# ----------------- Options -----------------
option(FILE_READ_UNSAFE "Disable path scope safety (allow reading outside config/rules)" OFF)
option(USING_MALLOC_TRIM "Call malloc_trim after processing request to lower memory usage" OFF)
option(BUILD_STATIC_LIBRARY "Build a static library containing only the essential part." OFF)

# ----------------- Check to_string -----------------
include(CheckCXXSourceCompiles)
check_cxx_source_compiles("
#include<string>
int main(){std::to_string(0);}
" HAVE_TO_STRING)

# ----------------- Sources -----------------
set(SHARED_SOURCES
    src/generator/config/ruleconvert.cpp
    src/generator/config/subexport.cpp
    src/generator/template/templates.cpp
    src/parser/subparser.cpp
    src/utils/base64/base64.cpp
    src/utils/codepage.cpp
    src/utils/logger.cpp
    src/utils/md5/md5.cpp
    src/utils/network.cpp
    src/utils/regexp.cpp
    src/utils/string.cpp
    src/utils/urlencode.cpp
)

if(BUILD_STATIC_LIBRARY)
    add_library(${BUILD_TARGET_NAME} STATIC
        ${SHARED_SOURCES}
        src/lib/wrapper.cpp
    )
    target_compile_definitions(${BUILD_TARGET_NAME} PRIVATE -DNO_JS_RUNTIME -DNO_WEBGET)
else()
    add_executable(${BUILD_TARGET_NAME}
        ${SHARED_SOURCES}
        src/generator/config/nodemanip.cpp
        src/handler/interfaces.cpp
        src/handler/multithread.cpp
        src/handler/upload.cpp
        src/handler/webget.cpp
        src/handler/settings.cpp
        src/main.cpp
        src/parser/infoparser.cpp
        src/script/cron.cpp
        src/script/script_quickjs.cpp
        src/server/webserver_httplib.cpp
        src/utils/file.cpp
        src/utils/system.cpp
    )
endif()

# ----------------- Definitions -----------------
if(FILE_READ_UNSAFE)
    target_compile_definitions(${BUILD_TARGET_NAME} PRIVATE -DFILE_READ_UNSAFE)
endif()

if(HAVE_TO_STRING)
    target_compile_definitions(${BUILD_TARGET_NAME} PRIVATE -DHAVE_TO_STRING)
endif()

if(USING_MALLOC_TRIM)
    target_compile_definitions(${BUILD_TARGET_NAME} PRIVATE -DMALLOC_TRIM)
endif()

# ----------------- Includes & Linking -----------------
target_include_directories(${BUILD_TARGET_NAME} PRIVATE src)
target_link_directories(${BUILD_TARGET_NAME} PRIVATE ${CMAKE_SOURCE_DIR})

# Threads
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(${BUILD_TARGET_NAME} PRIVATE ${CMAKE_THREAD_LIBS_INIT})

# CURL
find_package(CURL 7.54.0 REQUIRED)
target_include_directories(${BUILD_TARGET_NAME} PRIVATE ${CURL_INCLUDE_DIRS})
target_link_directories(${BUILD_TARGET_NAME} PRIVATE ${CURL_LIBRARY_DIRS})
target_link_libraries(${BUILD_TARGET_NAME} PRIVATE CURL::libcurl)
target_compile_definitions(${BUILD_TARGET_NAME} PRIVATE -DCURL_STATICLIB)

# RapidJSON
find_package(Rapidjson REQUIRED)
target_include_directories(${BUILD_TARGET_NAME} PRIVATE ${RAPIDJSON_INCLUDE_DIRS})

# toml11
find_package(toml11 REQUIRED)
target_include_directories(${BUILD_TARGET_NAME} PRIVATE ${TOML11_INCLUDE_DIRS})

# yaml-cpp (via pkg-config)
find_package(PkgConfig REQUIRED)
pkg_check_modules(YAML_CPP yaml-cpp>=0.6.3 REQUIRED)
find_library(YAML_CPP_LIBRARY NAMES yaml-cpp yaml-cppd PATHS ${YAML_CPP_LIBRARY_DIRS})
target_include_directories(${BUILD_TARGET_NAME} PRIVATE ${YAML_CPP_INCLUDE_DIRS})
target_link_directories(${BUILD_TARGET_NAME} PRIVATE ${YAML_CPP_LIBRARY_DIRS})
target_link_libraries(${BUILD_TARGET_NAME} PRIVATE ${YAML_CPP_LIBRARY})
target_compile_definitions(${BUILD_TARGET_NAME} PRIVATE -DYAML_CPP_STATIC_DEFINE)

# PCRE2
find_package(PCRE2 REQUIRED)
target_include_directories(${BUILD_TARGET_NAME} PRIVATE ${PCRE2_INCLUDE_DIRS})
target_link_libraries(${BUILD_TARGET_NAME} PRIVATE ${PCRE2_LIBRARY})
target_compile_definitions(${BUILD_TARGET_NAME} PRIVATE -DPCRE2_STATIC)

# QuickJS
if(NOT BUILD_STATIC_LIBRARY)
    find_package(QuickJS REQUIRED)
    target_include_directories(${BUILD_TARGET_NAME} PRIVATE ${QUICKJS_INCLUDE_DIRS})
    target_link_libraries(${BUILD_TARGET_NAME} PRIVATE ${QUICKJS_LIBRARIES})
endif()

# LibCron
find_package(LibCron REQUIRED)
target_include_directories(${BUILD_TARGET_NAME} PRIVATE ${LIBCRON_INCLUDE_DIRS})
target_link_libraries(${BUILD_TARGET_NAME} PRIVATE ${LIBCRON_LIBRARIES})

# Platform-specific
if(WIN32)
    target_link_libraries(${BUILD_TARGET_NAME} PRIVATE ws2_32 wsock32)
else()
    include(GNUInstallDirs)
    install(TARGETS ${BUILD_TARGET_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR}/${BUILD_TARGET_NAME})
    install(DIRECTORY base/ DESTINATION ${CMAKE_INSTALL_BINDIR}/${BUILD_TARGET_NAME} FILES_MATCHING PATTERN "*")
endif()
