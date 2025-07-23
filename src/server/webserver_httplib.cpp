#include <string>
#ifdef MALLOC_TRIM
#include <malloc.h>
#endif // MALLOC_TRIM
#define CPPHTTPLIB_REQUEST_URI_MAX_LENGTH 16384
#include "httplib.h"

#include "utils/base64/base64.h"
#include "utils/logger.h"
#include "utils/string_hash.h"
#include "utils/stl_extra.h"
#include "utils/urlencode.h"
#include "webserver.h"
//add
#include <array>
#include <sys/stat.h>
#ifdef _WIN32
#include <windows.h>
#endif

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_LEVEL_INFO
#endif
#define LOG_IF_LEVEL(level, msg) \
    do { if (LOG_LEVEL >= level) writeLog(0, msg, level); } while(0)

static bool isDirectory(const std::string &path) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && (attr & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat statbuf;
    if (stat(path.c_str(), &statbuf) != 0)
        return false;
    return S_ISDIR(statbuf.st_mode);
#endif
}
static const char *request_header_blacklist[] = {"host", "accept", "accept-encoding"};

static inline bool is_request_header_blacklisted(const std::string &header)
{
    for (auto &x : request_header_blacklist)
    {
        if (strcasecmp(x, header.c_str()) == 0)
        {
            return true;
        }
    }
    return false;
}

void WebServer::stop_web_server()
{
    SERVER_EXIT_FLAG = true;
}

static bool isValidIP(const std::string &ip)
{
    sockaddr_in sa4{};
    sockaddr_in6 sa6{};
    return inet_pton(AF_INET, ip.c_str(), &sa4.sin_addr) == 1 || inet_pton(AF_INET6, ip.c_str(), &sa6.sin6_addr) == 1;
}


static std::string extractFirstIP(const std::string &hdr, bool &found)
{
    size_t pos = 0;
    found = false;
    while (pos < hdr.length()) {
        size_t comma = hdr.find(',', pos);
        auto token = hdr.substr(pos, (comma == std::string::npos ? hdr.size() : comma) - pos);
        size_t b = token.find_first_not_of(" \t\r\n\"");
        size_t e = token.find_last_not_of(" \t\r\n\"");
        if (b != std::string::npos && e != std::string::npos) {
            auto ip = token.substr(b, e - b + 1);
            if (ip.length() > 2 && ip[0] == '[' && ip[ip.length() - 1] == ']') {
                ip = ip.substr(1, ip.length() - 2);
            }
            if (isValidIP(ip)) {
                found = true;
                return ip;
            }
        }
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }
    return "";
}


static std::string getClientRealIP(const httplib::Request &req)
{
    const char* header_groups[3][3] = {
        { "CF-Connecting-IP", "True-Client-IP", "Fastly-Client-IP" },
        { "X-Cluster-Client-IP", "X-Real-IP", "X-Forwarded-For" },
        { "X-Client-IP", "X-Originating-IP", "Forwarded" }
    };

    for (int i = 0; i < 3; ++i) {
        for (int j = 0; j < 3; ++j) {
            const char* hv = header_groups[i][j];
            if (!req.has_header(hv))
                continue;

            std::string val = req.get_header_value(hv);

            if (hv == "Forwarded") {
                std::string remaining = val;

                while (!remaining.empty()) {
                    size_t for_pos = remaining.find("for=");
                    if (for_pos == std::string::npos)
                        break;

                    remaining = remaining.substr(for_pos + 4);

                    bool quoted = false;
                    if (!remaining.empty() && remaining[0] == '"') {
                        quoted = true;
                        remaining = remaining.substr(1);
                    }

                    size_t end = remaining.find_first_of(quoted ? "\"" : ";,");
                    std::string ip_part = remaining.substr(0, end);

                    if (ip_part.length() > 2 && ip_part[0] == '[' && ip_part[ip_part.length() - 1] == ']') {
                        ip_part = ip_part.substr(1, ip_part.length() - 2);
                    }

                    if (isValidIP(ip_part)) {
                        return ip_part;
                    }

                    if (end == std::string::npos)
                        break;
                    remaining = remaining.substr(end + (quoted ? 1 : 0));
                }
            }

            bool found = false;
            std::string ip = extractFirstIP(val, found);
            if (found) {
                return ip;
            }
        }
    }

    return req.remote_addr;
}


static httplib::Server::Handler makeHandler(const responseRoute &rr)
{
    return [rr](const httplib::Request &request, httplib::Response &response)
    {
        Request req;
        Response resp;
        req.method = request.method;
        req.url = request.path;
        auto real_ip = getClientRealIP(request);
        for (auto &h: request.headers)
        {
            if (startsWith(h.first, "LOCAL_") || startsWith(h.first, "REMOTE_") || is_request_header_blacklisted(h.first))
            {
                continue;
            }
            req.headers.emplace(h.first.data(), h.second.data());
        }

        auto existing_xff = trim(request.get_header_value("X-Forwarded-For"));
        auto &xff = req.headers["X-Forwarded-For"];
        if (!existing_xff.empty())
        {
            if (existing_xff.find(real_ip) == std::string::npos)
            {
                xff = real_ip + ", " + existing_xff;
            }
            else
            {
                xff = existing_xff;
            }
        }
        else
        {
            xff = real_ip;
        }
        req.headers["X-Real-IP"] = real_ip;
        req.headers["MiaoKo-Connecting-IP"] = real_ip;
        req.argument = request.params;
        const auto &ct = request.get_header_value("Content-Type");
        if (request.method == "POST" || request.method == "PUT" || request.method == "PATCH")
        {
            if (request.is_multipart_form_data() && !request.files.empty())
            {
                req.postdata = request.files.begin()->second.content;
            }
            else if (ct.find("application/x-www-form-urlencoded") != std::string::npos)
            {
                req.postdata = urlDecode(request.body);
            }
            else
            {
                req.postdata = request.body;
            }
        }
        auto result = rr.rc(req, resp);
        response.status = resp.status_code;
        for (auto &h: resp.headers)
        {
            response.set_header(h.first, h.second);
        }
        auto content_type = resp.content_type;
        if (content_type.empty())
        {
            content_type = rr.content_type;
        }
        response.set_content(result, content_type);
    };
}

static std::string dump(const httplib::Headers &headers)
{
    std::string s;
    for (auto &x: headers)
    {
        if (startsWith(x.first, "LOCAL_") || startsWith(x.first, "REMOTE_"))
            continue;
        s += x.first + ": " + x.second + "|";
    }
    return s;
}

int WebServer::start_web_server_multi(listener_args *args)
{
    httplib::Server server;
    for (auto &x : responses)
    {
        switch (hash_(x.method))
        {
            case "GET"_hash: case "HEAD"_hash:
                server.Get(x.path, makeHandler(x));
                break;
            case "POST"_hash:
                server.Post(x.path, makeHandler(x));
                break;
            case "PUT"_hash:
                server.Put(x.path, makeHandler(x));
                break;
            case "DELETE"_hash:
                server.Delete(x.path, makeHandler(x));
                break;
            case "PATCH"_hash:
                server.Patch(x.path, makeHandler(x));
                break;
        }
    }
    server.Options(R"(.*)", [&](const httplib::Request &req, httplib::Response &res)
    {
        auto path = req.path;
        std::string allowed;
        for (auto &rr : responses)
        {
            if (rr.path == path)
            {
                allowed += rr.method + ",";
            }
        }
        if (!allowed.empty())
        {
            allowed.pop_back();
            res.status = 200;
            res.set_header("Access-Control-Allow-Methods", allowed);
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_header("Access-Control-Allow-Headers", "Content-Type,Authorization");
        }
        else
        {
            res.status = 404;
        } });
    server.set_pre_routing_handler([&](const httplib::Request &req, httplib::Response &res)
                                   {
        auto real_ip = getClientRealIP(req);

        LOG_IF_LEVEL(LOG_LEVEL_DEBUG,"Accept connection from client (real IP: " + real_ip + ", remote: " + req.remote_addr + ":" + std::to_string(req.remote_port) + ")");
        LOG_IF_LEVEL(LOG_LEVEL_VERBOSE,"handle_cmd:    " + req.method + " handle_uri:    " + req.target);
        LOG_IF_LEVEL(LOG_LEVEL_VERBOSE,"handle_header: " + dump(req.headers));

        if (req.has_header("SubConverter-Request"))
        {
            res.status = 500;
            res.set_content("Loop request detected!", "text/plain");
            return httplib::Server::HandlerResponse::Handled;
        }
        res.set_header("Server", "subconverter/" VERSION " cURL/" LIBCURL_VERSION);
        if (require_auth)
        {
            static std::string auth_token = "Basic " + base64Encode(auth_user + ":" + auth_password);
            auto auth = req.get_header_value("Authorization");
            if (auth != auth_token)
            {
                res.status = 401;
                res.set_header("WWW-Authenticate", "Basic realm=" + auth_realm + ", charset=\"UTF-8\"");
                res.set_content("Unauthorized", "text/plain");
                return httplib::Server::HandlerResponse::Handled;
            }
        }
        res.set_header("X-Client-IP", req.remote_addr);
        if (req.has_header("Access-Control-Request-Headers"))
        {
            res.set_header("Access-Control-Allow-Headers", req.get_header_value("Access-Control-Request-Headers"));
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        return httplib::Server::HandlerResponse::Unhandled;
    });
    for (auto &x : redirect_map)
    {
        server.Get(x.first, [x](const httplib::Request &req, httplib::Response &res) {
            auto arguments = req.params;
            auto query = x.second;
            auto pos = query.find('?');
            query += pos == std::string::npos ? '?' : '&';
            for (auto &p: arguments)
            {
                query += p.first + "=" + urlEncode(p.second) + "&";
            }
            if (!query.empty())
            {
                query.pop_back();
            }
            res.set_redirect(query);
        });
    }
    server.set_exception_handler([](const httplib::Request &req, httplib::Response &res, const std::exception_ptr &e)
    {
        try
        {
            if (e) std::rethrow_exception(e);
        }
        catch (const httplib::Error &err)
        {
            res.set_content(to_string(err), "text/plain");
        }
        catch (const std::exception &ex)
        {
            std::string return_data = "Internal server error while processing request '" + req.target + "'!\n";
            return_data += "\n  exception: ";
            return_data += type(ex);
            return_data += "\n  what(): ";
            return_data += ex.what();
            res.status = 500;
            res.set_content(return_data, "text/plain");
        }
        catch (...)
        {
            res.status = 500;
        } });
    if (serve_file && isDirectory(serve_file_root))
    {
        server.set_mount_point("/", serve_file_root);
    }
    server.new_task_queue = [args] {
        return new httplib::ThreadPool(args->max_workers);
    };
    server.bind_to_port(args->listen_address, args->port, 0);

    std::thread thread([&]()
    {
        server.listen_after_bind();
    });

    while (!SERVER_EXIT_FLAG)
    {
        if (args->looper_callback)
        {
            args->looper_callback();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(args->looper_interval));
    }

    server.stop();
    thread.join();
    return 0;
}

int WebServer::start_web_server(listener_args *args)
{
    return start_web_server_multi(args);
}
