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
#define LOG_IF_LEVEL(level, msg) \
    do { if (LOG_LEVEL >= level) writeLog(0, msg, level); } while(0)

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

static bool isValidIP(std::string_view ip)
{
    sockaddr_in sa4{};
    sockaddr_in6 sa6{};
    std::string tmp(ip);
    return inet_pton(AF_INET, tmp.c_str(), &sa4.sin_addr) == 1 || inet_pton(AF_INET6, tmp.c_str(), &sa6.sin6_addr) == 1;
}

static std::optional<std::string> extractFirstIP(std::string_view hdr)
{
    size_t pos = 0;
    while (pos < hdr.size())
    {
        size_t comma = hdr.find(',', pos);
        auto token = hdr.substr(pos, (comma == std::string_view::npos ? hdr.size() : comma) - pos);
        size_t b = token.find_first_not_of(" \t\r\n\"");
        size_t e = token.find_last_not_of(" \t\r\n\"");
        if (b != std::string_view::npos && e != std::string_view::npos)
        {
            auto ip = token.substr(b, e - b + 1);

            if (ip.front() == '[' && ip.back() == ']')
            {
                ip.remove_prefix(1);
                ip.remove_suffix(1);
            }

            if (isValidIP(ip))
            {
                return std::string(ip);
            }
        }
        if (comma == std::string_view::npos)
            break;
        pos = comma + 1;
    }
    return std::nullopt;
}

static std::string getClientRealIP(const httplib::Request &req)
{
    static constexpr std::array<std::array<std::string_view, 3>, 3> header_groups{{
        {"CF-Connecting-IP", "True-Client-IP", "Fastly-Client-IP"},
        {"X-Cluster-Client-IP", "X-Real-IP", "X-Forwarded-For"},
        {"X-Client-IP", "X-Originating-IP", "Forwarded"}
    }};

    for (const auto &group : header_groups)
    {
        for (auto hv : group)
        {
            if (!req.has_header(hv))
                continue;
            auto val = req.get_header_value(hv);

            if (hv == "Forwarded")
            {
                std::string_view remaining = val;

                while (!remaining.empty())
                {
                    auto for_pos = remaining.find("for=");
                    if (for_pos == std::string_view::npos)
                        break;

                    remaining.remove_prefix(for_pos + 4);

                    bool quoted = false;
                    if (!remaining.empty() && remaining.front() == '"')
                    {
                        quoted = true;
                        remaining.remove_prefix(1);
                    }
                    auto end = remaining.find_first_of(quoted ? "\"" : ";,");
                    auto ip_part = remaining.substr(0, end);

                    if (ip_part.size() >= 2 && ip_part.front() == '[' && ip_part.back() == ']')
                    {
                        ip_part.remove_prefix(1);
                        ip_part.remove_suffix(1);
                    }

                    if (isValidIP(ip_part))
                    {
                        return std::string(ip_part);
                    }

                    if (end == std::string_view::npos)
                        break;
                    remaining.remove_prefix(end + (quoted ? 1 : 0));
                }
            }

            if (auto ip = extractFirstIP(val); ip.has_value())
            {
                return *ip;
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
    if (serve_file && std::filesystem::is_directory(serve_file_root))
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
