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
#include <array>
#include <algorithm>
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
    if (ip.empty() || ip.length() > 45) return false;
    
    // 检查是否包含IPv6特征字符
    bool hasColon = ip.find(':') != std::string::npos;
    
    if (hasColon) {
        sockaddr_in6 sa6{};
        return inet_pton(AF_INET6, ip.c_str(), &sa6.sin6_addr) == 1;
    } else {
        sockaddr_in sa4{};
        return inet_pton(AF_INET, ip.c_str(), &sa4.sin_addr) == 1;
    }
}

static std::string extractFirstIP(const std::string &hdr, bool &found)
{
    found = false;
    size_t start = 0;

    start = hdr.find_first_not_of(" \t\r\n,");
    if (start == std::string::npos) return "";

    size_t end = 0;

    while (start < hdr.length()) {
        end = hdr.find_first_of(",", start);
        if (end == std::string::npos) end = hdr.length();

        std::string candidate = hdr.substr(start, end - start);
        candidate = trimWhitespace(candidate,true,true);

        if (!candidate.empty() && candidate.front() == '[' && candidate.back() == ']') {
            candidate = candidate.substr(1, candidate.length() - 2);
        }

        if (isValidIP(candidate)) {
            found = true;
            return candidate;
        }

        start = hdr.find_first_not_of(" \t\r\n,", end + 1);
        if (start == std::string::npos) break;
    }

    return "";
}

static std::string getClientRealIP(const httplib::Request &req)
{
    const std::vector<std::vector<std::string>> headerGroups = {
        { "CF-Connecting-IP", "Fly-Client-IP", "True-Client-IP", "Fastly-Client-IP", 
          "CDN-Connecting-IP", "Cdn-Src-Ip", "Tencent-Client-IP", "Ali-CDN-Real-IP",
          "AWS-Client-IP", "Azure-ClientIP", "X-Cloudinary-Real-IP", "X-EC-Client-IP",
          "X-KeysCDN-Connecting-IP", "X-Sucuri-ClientIP", "Cdn-Real-Ip", "X-Cache-Client-IP",
          "X-Kakao-Real-IP", "CDN-Client-IP" },
        { "X-Forwarded-For", "X-Cluster-Client-IP", "X-Real-IP", "X-Forwarded-For-Tencent", "X-Real-IP-Alibabacloud" },
        { "X-Client-IP", "X-Originating-IP", "Forwarded" }
    };

    for (const auto& group : headerGroups) {
        for (const auto& header : group) {
            if (!req.has_header(header.c_str()))
                continue;

            std::string value = req.get_header_value(header.c_str());

            if (header == "Forwarded") {
                size_t pos = 0;
                while (pos < value.size()) {
                    size_t forPos = value.find("for=", pos);
                    if (forPos == std::string::npos) break;
                    forPos += 4;

                    bool isQuoted = (forPos < value.size() && value[forPos] == '"');
                    if (isQuoted) ++forPos;

                    size_t endPos = value.find(isQuoted ? '"' : ';', forPos);
                    if (endPos == std::string::npos) endPos = value.size();

                    std::string ipCandidate = value.substr(forPos, endPos - forPos);
                    
                    // 移除IPv6方括号
                    if (!ipCandidate.empty() && ipCandidate.front() == '[' && ipCandidate.back() == ']') {
                        ipCandidate = ipCandidate.substr(1, ipCandidate.size() - 2);
                    }

                    if (isValidIP(ipCandidate))
                        return ipCandidate;

                    pos = endPos + (isQuoted ? 1 : 0);
                }
            }
            else if (header == "X-Forwarded-For" || header == "X-Forwarded-For-Tencent") {
                size_t commaPos = value.find(',');
                std::string firstIp = commaPos != std::string::npos 
                    ? value.substr(0, commaPos) 
                    : value;
                
                firstIp.erase(0, firstIp.find_first_not_of(" \t"));
                firstIp.erase(firstIp.find_last_not_of(" \t") + 1);
                
                if (isValidIP(firstIp))
                    return firstIp;
            }
            else {
                bool found = false;
                std::string ip = extractFirstIP(value, found);
                if (found && isValidIP(ip))
                    return ip;
            }
        }
    }

    return req.remote_addr;
}

static std::string limitXFFIPs(const std::string& xff, const std::string& newIP, size_t maxIPs = 4) {
    std::vector<std::string> ips;
    ips.push_back(newIP);
    
    size_t pos = 0;
    while (pos < xff.length()) {
        size_t comma = xff.find(',', pos);
        std::string ip = xff.substr(pos, comma == std::string::npos ? xff.length() - pos : comma - pos);
        ip = trimWhitespace(ip, true, true);
        
        if (!ip.empty()) {
            std::string lower_ip = ip;
            std::transform(lower_ip.begin(), lower_ip.end(), lower_ip.begin(), ::tolower);
            
            bool isDuplicate = false;
            for (const auto& existing : ips) {
                std::string lower_existing = existing;
                std::transform(lower_existing.begin(), lower_existing.end(), lower_existing.begin(), ::tolower);
                if (lower_existing == lower_ip) {
                    isDuplicate = true;
                    break;
                }
            }
            
            if (!isDuplicate) {
                ips.push_back(ip);
            }
        }
        
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }
    
    if (ips.size() > maxIPs) {
        ips.erase(ips.begin() + maxIPs, ips.end());
    }
    
    std::string result;
    for (size_t i = 0; i < ips.size(); ++i) {
        result += ips[i];
        if (i < ips.size() - 1) {
            result += ", ";
        }
    }
    
    return result;
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
        
        auto& headers = req.headers;
        const std::string existing_xff = trimWhitespace(headers["X-Forwarded-For"],true, true);
        headers["X-Client-IP"] = real_ip;
        headers["X-Forwarded-For"] = limitXFFIPs(existing_xff, real_ip, 4);
        headers["X-Real-IP"] = real_ip;
        headers["FFQ-Connecting-IP"] = real_ip;

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
