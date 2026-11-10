#pragma once

#include <functional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace web {
using Json = nlohmann::json;
struct Url { std::string value, scheme, host, port, origin; };
struct Options {
    std::string url, ca_file, connect_ip, json_path, markdown_path;
    std::vector<std::string> allow_origins;
    int timeout_ms = 5000;
    int max_redirects = 5;
    bool no_banner = false;
};
struct Header { std::string name, value; };
struct Response {
    std::string url, ip, error, tls_state = "not_applicable";
    long status = 0;
    long long elapsed_ms = 0;
    bool headers_complete = false, body_truncated = false;
    std::vector<Header> headers;
    Json certificates = Json::array();
};
struct Capture {
    Response response;
    std::size_t header_bytes = 0, body_bytes = 0;
    bool limit_error = false, callback_error = false;
};
using Fetch = std::function<Response(const Url&, const Options&)>;
void initialize();
Url parse_url(const std::string& value, const std::string& base = "");
Options parse_options(int argc, char* argv[]);
std::string help();
std::size_t receive_header(char*, std::size_t, std::size_t, void*) noexcept;
std::size_t receive_body(char*, std::size_t, std::size_t, void*) noexcept;
Response fetch(const Url&, const Options&);
Json cookies(const Response&);
Json findings(const Response&);
Json inspect(const Options&, const Fetch& transport = fetch);
std::string markdown(const Json& report);
std::string safe_text(const std::string& value);
void validate_outputs(const Options&);
void write_new_file(const std::string& path, const std::string& data);
int run(int argc, char* argv[]);
}
