#include "web.hpp"

#include <chrono>
#include <curl/curl.h>
#include <limits>
#include <memory>
#include <stdexcept>

namespace web {
namespace {
constexpr std::size_t limit = 65536;
std::string trim(std::string text)
{
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) { return {}; }
    return text.substr(first, text.find_last_not_of(" \t\r\n") - first + 1);
}
template<typename T> void option(CURL* curl, CURLoption key, T value)
{
    const auto code = curl_easy_setopt(curl, key, value);
    if (code != CURLE_OK) { throw std::runtime_error(curl_easy_strerror(code)); }
}
}
std::size_t receive_header(char* data, std::size_t size, std::size_t count, void* user) noexcept
{
    auto& capture = *static_cast<Capture*>(user);
    try {
        if (size != 0 && count > std::numeric_limits<std::size_t>::max() / size) { capture.limit_error = true; return 0; }
        const auto bytes = size * count;
        if (bytes > limit - capture.header_bytes) { capture.limit_error = true; return 0; }
        capture.header_bytes += bytes;
        std::string line(data, bytes);
        if (line.rfind("HTTP/", 0) == 0) {
            capture.response.headers.clear();
            capture.response.headers_complete = false;
        } else if (line == "\r\n" || line == "\n") {
            capture.response.headers_complete = true;
        } else if (!capture.response.headers_complete) {
            if (capture.response.headers.size() >= 200) { capture.limit_error = true; return 0; }
            const auto colon = line.find(':');
            if (colon == std::string::npos || colon == 0 || line.front() == ' ' || line.front() == '\t') {
                capture.callback_error = true; return 0;
            }
            capture.response.headers.push_back({trim(line.substr(0, colon)), trim(line.substr(colon + 1))});
        }
        return bytes;
    } catch (...) { capture.callback_error = true; return 0; }
}
std::size_t receive_body(char*, std::size_t size, std::size_t count, void* user) noexcept
{
    auto& capture = *static_cast<Capture*>(user);
    if (size != 0 && count > std::numeric_limits<std::size_t>::max() / size) { capture.response.body_truncated = true; return 0; }
    const auto bytes = size * count;
    if (bytes > limit - capture.body_bytes) { capture.response.body_truncated = true; return 0; }
    capture.body_bytes += bytes;
    return bytes;
}
Response fetch(const Url& url, const Options& options)
{
    initialize();
    Capture capture;
    capture.response.url = url.value;
    if (url.scheme == "https") { capture.response.tls_state = "not_established"; }
    // Lists must outlive the easy handle that refers to them.
    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> resolution(nullptr, curl_slist_free_all);
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
    if (!curl) { throw std::bad_alloc(); }
    char error[CURL_ERROR_SIZE]{};
    option(curl.get(), CURLOPT_URL, url.value.c_str());
    option(curl.get(), CURLOPT_PROTOCOLS_STR, "http,https");
    option(curl.get(), CURLOPT_FOLLOWLOCATION, 0L);
    option(curl.get(), CURLOPT_PROXY, "");
    option(curl.get(), CURLOPT_NETRC, static_cast<long>(CURL_NETRC_IGNORED));
    option(curl.get(), CURLOPT_USERAGENT, "zerosee/0.2.0");
    option(curl.get(), CURLOPT_NOSIGNAL, 1L);
    option(curl.get(), CURLOPT_TIMEOUT_MS, static_cast<long>(options.timeout_ms));
    option(curl.get(), CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(options.timeout_ms));
    option(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    option(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);
    option(curl.get(), CURLOPT_CERTINFO, 1L);
    option(curl.get(), CURLOPT_HEADERFUNCTION, receive_header);
    option(curl.get(), CURLOPT_HEADERDATA, &capture);
    option(curl.get(), CURLOPT_WRITEFUNCTION, receive_body);
    option(curl.get(), CURLOPT_WRITEDATA, &capture);
    option(curl.get(), CURLOPT_ERRORBUFFER, error);
    if (!options.ca_file.empty()) { option(curl.get(), CURLOPT_CAINFO, options.ca_file.c_str()); }
    if (!options.connect_ip.empty() && url.host == parse_url(options.url).host) {
        const auto rule = url.host + ":" + url.port + ":" + options.connect_ip;
        resolution.reset(curl_slist_append(nullptr, rule.c_str()));
        if (!resolution) { throw std::bad_alloc(); }
        option(curl.get(), CURLOPT_RESOLVE, resolution.get());
    }
    const auto start = std::chrono::steady_clock::now();
    const auto code = curl_easy_perform(curl.get());
    auto& response = capture.response;
    response.elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &response.status);
    char* ip = nullptr;
    curl_easy_getinfo(curl.get(), CURLINFO_PRIMARY_IP, &ip);
    if (ip) { response.ip = ip; }
    if (url.scheme == "https") {
        if (code == CURLE_PEER_FAILED_VERIFICATION) { response.tls_state = "verification_failed"; }
        else if (response.status != 0 || code == CURLE_OK) { response.tls_state = "verified"; }
        curl_certinfo* info = nullptr;
        if (curl_easy_getinfo(curl.get(), CURLINFO_CERTINFO, &info) == CURLE_OK && info) {
            for (int i = 0; i < info->num_of_certs && i < 16; ++i) {
                Json certificate = Json::object();
                for (auto* field = info->certinfo[i]; field; field = field->next) {
                    const std::string value(field->data);
                    const auto colon = value.find(':');
                    if (colon == std::string::npos || value.size() > 8192) { continue; }
                    const auto name = value.substr(0, colon);
                    if (name != "Cert") { certificate[name] = value.substr(colon + 1); }
                }
                response.certificates.push_back(certificate);
            }
        }
    }
    if (capture.limit_error) { response.error = "Header size/count limit exceeded"; response.headers_complete = false; }
    else if (capture.callback_error) { response.error = "Malformed headers or callback allocation failure"; response.headers_complete = false; }
    else if (code != CURLE_OK && !(code == CURLE_WRITE_ERROR && response.body_truncated && response.headers_complete)) {
        response.error = error[0] ? error : curl_easy_strerror(code);
    }
    return response;
}
}
