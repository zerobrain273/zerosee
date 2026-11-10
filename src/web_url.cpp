#include "web.hpp"

#include <arpa/inet.h>
#include <charconv>
#include <cctype>
#include <curl/curl.h>
#include <filesystem>
#include <memory>
#include <set>
#include <stdexcept>

namespace web {
void initialize()
{
    struct Runtime {
        Runtime() { if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) { throw std::runtime_error("libcurl initialization failed"); } }
        ~Runtime() { curl_global_cleanup(); }
    };
    static Runtime runtime;
}
namespace {
std::string part(CURLU* url, CURLUPart field, unsigned flags = 0)
{
    char* raw = nullptr;
    if (curl_url_get(url, field, &raw, flags) != CURLUE_OK) { return {}; }
    std::unique_ptr<char, decltype(&curl_free)> text(raw, curl_free);
    return text.get();
}
int number(const std::string& text, int minimum, int maximum, const std::string& flag)
{
    int value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || value < minimum || value > maximum) {
        throw std::invalid_argument(flag + " must be between " + std::to_string(minimum) + " and " + std::to_string(maximum));
    }
    return value;
}
}
Url parse_url(const std::string& value, const std::string& base)
{
    initialize();
    if (value.empty() || value.size() > 8192) { throw std::invalid_argument("URL must contain 1-8192 bytes"); }
    for (unsigned char c : value) {
        if (c <= 32 || c == 127 || c == '\\') { throw std::invalid_argument("URL contains whitespace, controls or backslash"); }
    }
    std::unique_ptr<CURLU, decltype(&curl_url_cleanup)> url(curl_url(), curl_url_cleanup);
    if (!url) { throw std::bad_alloc(); }
    if (!base.empty() && curl_url_set(url.get(), CURLUPART_URL, base.c_str(), CURLU_DISALLOW_USER) != CURLUE_OK) {
        throw std::invalid_argument("Invalid base URL");
    }
    if (base.empty() && value.find("://") == std::string::npos) { throw std::invalid_argument("Specify http:// or https:// explicitly"); }
    if (curl_url_set(url.get(), CURLUPART_URL, value.c_str(), CURLU_DISALLOW_USER) != CURLUE_OK) {
        throw std::invalid_argument("Invalid URL; credentials in URLs are not supported");
    }
    Url result;
    result.scheme = part(url.get(), CURLUPART_SCHEME);
    if (result.scheme != "http" && result.scheme != "https") { throw std::invalid_argument("Only HTTP and HTTPS are supported"); }
    result.host = part(url.get(), CURLUPART_HOST);
    if (result.host.empty() || !part(url.get(), CURLUPART_ZONEID).empty()) { throw std::invalid_argument("Invalid host or unsupported IPv6 zone"); }
    for (auto& c : result.host) {
        if (static_cast<unsigned char>(c) >= 128) { throw std::invalid_argument("Use ASCII/punycode hostnames"); }
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    result.port = part(url.get(), CURLUPART_PORT, CURLU_DEFAULT_PORT);
    number(result.port, 1, 65535, "URL port");
    curl_url_set(url.get(), CURLUPART_HOST, result.host.c_str(), 0);
    curl_url_set(url.get(), CURLUPART_FRAGMENT, nullptr, 0);
    result.value = part(url.get(), CURLUPART_URL, CURLU_NO_DEFAULT_PORT);
    result.origin = result.scheme + "://" + result.host + ":" + result.port;
    return result;
}
Options parse_options(int argc, char* argv[])
{
    if (argc < 3) { throw std::invalid_argument("Expected: zerosee web <http(s)://URL>"); }
    Options options;
    options.url = parse_url(argv[2]).value;
    std::set<std::string> seen;
    for (int i = 3; i < argc; ++i) {
        std::string flag(argv[i]);
        if (flag == "-t") { flag = "--timeout-ms"; }
        if (flag == "--no-banner") {
            if (!seen.insert(flag).second) { throw std::invalid_argument("Duplicate " + flag); }
            options.no_banner = true;
            continue;
        }
        if (flag != "--allow-origin" && flag != "--timeout-ms" && flag != "--max-redirects"
            && flag != "--ca-file" && flag != "--connect-ip" && flag != "--json" && flag != "--markdown") {
            throw std::invalid_argument("Unknown web option: " + safe_text(flag));
        }
        if (flag != "--allow-origin" && !seen.insert(flag).second) { throw std::invalid_argument("Duplicate " + flag); }
        if (++i >= argc || std::string(argv[i]).empty()) { throw std::invalid_argument("Missing value for " + flag); }
        const std::string value(argv[i]);
        if (flag == "--timeout-ms") { options.timeout_ms = number(value, 1, 60000, flag); }
        else if (flag == "--max-redirects") { options.max_redirects = number(value, 0, 10, flag); }
        else if (flag == "--allow-origin") {
            const auto allowed = parse_url(value);
            if (allowed.value != allowed.scheme + "://" + allowed.host + (allowed.port == (allowed.scheme == "https" ? "443" : "80") ? "" : ":" + allowed.port) + "/") {
                throw std::invalid_argument("--allow-origin accepts scheme://host[:port] without path or query");
            }
            if (options.allow_origins.size() >= 16) { throw std::invalid_argument("At most 16 extra origins are allowed"); }
            options.allow_origins.push_back(allowed.origin);
        }
        else if (flag == "--connect-ip") {
            in_addr address{};
            if (inet_pton(AF_INET, value.c_str(), &address) != 1) { throw std::invalid_argument("--connect-ip requires an IPv4 address"); }
            options.connect_ip = value;
        }
        else if (flag == "--ca-file") {
            if (!std::filesystem::is_regular_file(value)) { throw std::invalid_argument("CA file does not exist or is not a regular file"); }
            options.ca_file = value;
        }
        else if (flag == "--json") { options.json_path = value; }
        else { options.markdown_path = value; }
    }
    validate_outputs(options);
    return options;
}
std::string help()
{
    return "Usage: zerosee web <http(s)://URL> [options]\n\n"
        "  -h, --help              Show web help.\n"
        "  -t, --timeout-ms N      Deadline per request, 1-60000 (default 5000).\n"
        "      --max-redirects N   Follow at most 0-10 redirects (default 5).\n"
        "      --allow-origin URL  Permit an extra exact origin; repeatable.\n"
        "      --connect-ip IPv4   Pin the initial URL hostname to this IP; preserves SNI/Host.\n"
        "      --ca-file PATH      Trust this CA bundle (for private/lab PKI).\n"
        "      --json PATH         Create a JSON report; never overwrite.\n"
        "      --markdown PATH     Create a Markdown report; never overwrite.\n"
        "      --no-banner         Hide the banner.\n\n"
        "Default scope: original scheme + host + port. HTTPS downgrades are always blocked.\n"
        "GET only; no cookies/auth replay. TLS verification is always enabled.\n"
        "Limits per request: 64 KiB headers, 200 fields, 64 KiB body (discarded).\n"
        "Proxy environment variables are ignored. Findings are observations, not exploit proof.\n";
}
}
