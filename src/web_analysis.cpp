#include "web.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <ctime>
#include <set>
#include <sstream>

namespace web {
namespace {
std::string lower(std::string value)
{
    for (char& c : value) { c = static_cast<char>(std::tolower(static_cast<unsigned char>(c))); }
    return value;
}
std::string trim(std::string value)
{
    const auto start = value.find_first_not_of(" \t");
    return start == std::string::npos ? "" : value.substr(start, value.find_last_not_of(" \t") - start + 1);
}
std::vector<std::string> values(const Response& response, const std::string& name)
{
    std::vector<std::string> result;
    for (const auto& header : response.headers) { if (lower(header.name) == name) { result.push_back(header.value); } }
    return result;
}
bool directive(const std::string& policy, const std::string& wanted)
{
    std::istringstream input(lower(policy));
    std::string item;
    while (std::getline(input, item, ';')) {
        std::istringstream tokens(item);
        std::string name, value;
        if (tokens >> name >> value && name == wanted) { return true; }
    }
    return false;
}
Json headers_json(const Response& response)
{
    Json result = Json::array();
    for (const auto& header : response.headers) {
        const auto name = lower(header.name);
        const bool sensitive = name == "set-cookie" || name == "authorization" || name == "proxy-authorization";
        result.push_back({{"name", header.name}, {"value", sensitive ? "[redacted]" : header.value}});
    }
    return result;
}
std::string timestamp()
{
    const auto now = std::time(nullptr);
    std::tm utc{};
    gmtime_r(&now, &utc);
    char text[32]{};
    std::strftime(text, sizeof(text), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return text;
}
}
Json cookies(const Response& response)
{
    Json result = Json::array();
    for (const auto& header : values(response, "set-cookie")) {
        std::istringstream stream(header);
        std::string first;
        std::getline(stream, first, ';');
        const auto equal = first.find('=');
        if (equal == std::string::npos || trim(first.substr(0, equal)).empty()) {
            result.push_back({{"name", "[unparsed]"}, {"value", "[redacted]"}, {"parsed", false}});
            continue;
        }
        Json cookie = {{"name", trim(first.substr(0, equal))}, {"value", "[redacted]"}, {"parsed", true},
            {"secure", false}, {"http_only", false}, {"same_site", ""}, {"domain", ""}, {"path", ""}, {"domain_present", false}};
        std::string attribute;
        while (std::getline(stream, attribute, ';')) {
            const auto split = attribute.find('=');
            const auto name = lower(trim(attribute.substr(0, split)));
            const auto value = split == std::string::npos ? "" : trim(attribute.substr(split + 1));
            if (name == "secure") { cookie["secure"] = true; }
            else if (name == "httponly") { cookie["http_only"] = true; }
            else if (name == "samesite") { cookie["same_site"] = lower(value); }
            else if (name == "domain") { cookie["domain"] = value; cookie["domain_present"] = true; }
            else if (name == "path") { cookie["path"] = value; }
        }
        result.push_back(cookie);
    }
    return result;
}
Json findings(const Response& response)
{
    Json result = Json::array();
    auto add = [&](const std::string& id, const std::string& level, const std::string& title,
                   const std::string& evidence, const std::string& context, const std::string& recommendation) {
        result.push_back({{"id", id}, {"level", level}, {"title", title}, {"url", response.url},
            {"evidence", evidence}, {"context", context}, {"recommendation", recommendation}});
    };
    if (response.tls_state == "verification_failed") {
        add("tls-verification-failed", "review", "TLS identity/trust verification failed", response.error,
            "The client could not validate the certificate chain or hostname. A private CA or local clock may explain this; no insecure retry was made.",
            "Check hostname/SAN, validity dates, issuer chain and the intended CA bundle.");
    }
    if (!response.error.empty() || !response.headers_complete || response.status < 200) { return result; }
    const bool https = parse_url(response.url).scheme == "https";
    const auto content_types = values(response, "content-type");
    const bool html = std::any_of(content_types.begin(), content_types.end(), [](const auto& value) {
        const auto type = lower(trim(value.substr(0, value.find(';'))));
        return type == "text/html" || type == "application/xhtml+xml";
    });
    if (!https) {
        add("cleartext-http", "info", "Response delivered over HTTP", "URL scheme is http",
            "This connection is unencrypted. The endpoint may exist only to redirect to HTTPS; sensitive data exposure was not tested.",
            "Use HTTPS for sensitive content and review the redirect chain.");
    }
    if (https && values(response, "strict-transport-security").empty()) {
        add("hsts-missing", "review", "No HSTS header observed", "Strict-Transport-Security absent on this response",
            "One response does not establish site-wide policy; preload status and parent-domain policies were not checked.",
            "Consider HSTS after confirming HTTPS coverage and subdomain requirements.");
    }
    const auto hsts = values(response, "strict-transport-security");
    if (https && !hsts.empty()) {
        std::istringstream parts(hsts.front());
        std::string item;
        while (std::getline(parts, item, ';')) {
            const auto equal = item.find('=');
            if (equal == std::string::npos || lower(trim(item.substr(0, equal))) != "max-age") { continue; }
            auto number = trim(item.substr(equal + 1));
            if (number.size() >= 2 && number.front() == '"' && number.back() == '"') { number = number.substr(1, number.size() - 2); }
            unsigned long long age = 1;
            const auto [end, error] = std::from_chars(number.data(), number.data() + number.size(), age);
            if (error == std::errc{} && end == number.data() + number.size() && age == 0) {
                add("hsts-disabled", "review", "HSTS max-age is zero", hsts.front(),
                    "This response requests removal of the host's dynamic HSTS policy; parent/preload policies may still apply.",
                    "Confirm that disabling HSTS is intentional.");
            }
        }
    }
    const auto csp = values(response, "content-security-policy");
    if (html && response.status >= 200 && response.status < 300) {
        if (csp.empty()) {
            add("csp-missing", "review", "No enforced CSP header on HTML", "Content-Security-Policy absent",
                "The body is not analysed; a meta CSP may exist. Absence of this header does not demonstrate XSS.",
                "Review application script requirements before deploying an enforced CSP.");
        }
        const bool ancestors = std::any_of(csp.begin(), csp.end(), [](const auto& value) { return directive(value, "frame-ancestors"); });
        if (values(response, "x-frame-options").empty() && !ancestors) {
            add("frame-policy-missing", "review", "No frame restriction header observed", "No X-Frame-Options or CSP frame-ancestors directive",
                "Whether framing is harmful depends on the page's actions and intended embedding. Clickjacking was not demonstrated.",
                "Review intended embedding and set an appropriate frame-ancestors policy.");
        }
        const auto nosniff = values(response, "x-content-type-options");
        if (nosniff.empty() || lower(trim(nosniff.front())) != "nosniff") {
            add("nosniff-missing", "review", "nosniff not observed", "X-Content-Type-Options is absent or not nosniff",
                "This is a hardening observation, not evidence of executable content injection.",
                "Serve correct MIME types and consider X-Content-Type-Options: nosniff.");
        }
    }
    for (const auto& cookie : cookies(response)) {
        if (!cookie.at("parsed").get<bool>()) { continue; }
        const auto name = cookie.at("name").get<std::string>();
        const bool secure = cookie.at("secure").get<bool>();
        const bool http_only = cookie.at("http_only").get<bool>();
        const auto same_site = cookie.at("same_site").get<std::string>();
        if (!secure) {
            add("cookie-secure-missing", "review", "Cookie lacks Secure", "Set-Cookie name=" + name + "; Secure absent",
                "Cookie value and purpose are not analysed. Transport impact depends on browser policy and endpoint usage.",
                "Use Secure for cookies that should only travel over HTTPS.");
        }
        if (!http_only) {
            add("cookie-httponly-missing", "review", "Cookie lacks HttpOnly", "Set-Cookie name=" + name + "; HttpOnly absent",
                "Some cookies intentionally need JavaScript access; this does not establish a session theft vulnerability.",
                "Use HttpOnly for session cookies that do not need JavaScript access.");
        }
        if (same_site.empty() || (same_site != "none" && same_site != "lax" && same_site != "strict")) {
            add("cookie-samesite-review", "review", "Cookie SameSite policy needs review", "Set-Cookie name=" + name + "; SameSite=" + same_site,
                "Browser defaults and application cross-site flows vary. This alone does not demonstrate CSRF.",
                "Choose an explicit SameSite policy compatible with authentication flows.");
        }
        if (same_site == "none" && !secure) {
            add("cookie-none-without-secure", "review", "SameSite=None without Secure", "Set-Cookie name=" + name,
                "Modern browsers may reject this cookie; browser acceptance is not tested.", "Pair SameSite=None with Secure over HTTPS.");
        }
        const bool host_prefix = name.rfind("__Host-", 0) == 0;
        const bool secure_prefix = name.rfind("__Secure-", 0) == 0;
        if ((host_prefix || secure_prefix) && (!https || !secure ||
            (host_prefix && (cookie.at("domain_present").get<bool>() || cookie.at("path") != "/")))) {
            add("cookie-prefix-invalid", "review", "Cookie prefix requirements not met", "Set-Cookie name=" + name,
                "Prefix validation is browser-dependent; rejection or exploitability was not tested.",
                "Use HTTPS and Secure; __Host- also requires Path=/ and no Domain attribute.");
        }
    }
    for (const auto& name : {"server", "x-powered-by"}) {
        for (const auto& value : values(response, name)) {
            add("technology-disclosure", "info", "Technology hint in response", std::string(name) + ": " + value,
                "Headers may be inaccurate or altered by a proxy. No version-to-CVE matching is performed.",
                "Treat this as a reconnaissance lead and verify the actual deployment.");
        }
    }
    return result;
}
Json inspect(const Options& options, const Fetch& transport)
{
    Url current = parse_url(options.url);
    std::set<std::string> allowed{current.origin}, visited;
    allowed.insert(options.allow_origins.begin(), options.allow_origins.end());
    Json report = {{"schema_version", 1}, {"tool", "zerosee"}, {"version", "0.2.0"}, {"started_at", timestamp()},
        {"target", current.value}, {"scope", allowed}, {"timeout_ms", options.timeout_ms},
        {"max_redirects", options.max_redirects}, {"connect_ip", options.connect_ip},
        {"trust_store", options.ca_file.empty() ? "system" : options.ca_file},
        {"hops", Json::array()}, {"findings", Json::array()}, {"stop_reason", ""},
        {"limitations", {"Unauthenticated GET observations only; no crawling or exploitation.",
            "Bodies are discarded; CSP meta tags and application behaviour are not evaluated.",
            "Cookie values are redacted and never replayed; URLs/other headers may still contain sensitive data.",
            "TLS checks use libcurl's configured trust store and hostname verification; revocation and cipher enumeration are not claimed.",
            "Origin scope is a URL boundary, not an IP allowlist; DNS is used unless --connect-ip pins the original hostname.",
            "At most 64 KiB headers, 200 fields and 64 KiB body per request; additional redirects are bounded."}}};
    for (int step = 0; ; ++step) {
        visited.insert(current.value);
        auto response = transport(current, options);
        response.url = current.value;
        const auto observed = findings(response);
        for (const auto& finding : observed) { report["findings"].push_back(finding); }
        report["hops"].push_back({{"url", current.value}, {"status", response.status}, {"ip", response.ip},
            {"elapsed_ms", response.elapsed_ms}, {"headers_complete", response.headers_complete},
            {"body_truncated", response.body_truncated}, {"error", response.error},
            {"tls", {{"state", response.tls_state}, {"certificates", response.certificates}}},
            {"headers", headers_json(response)}, {"cookies", cookies(response)}});
        auto& hop = report["hops"].back();
        if (!response.error.empty() || !response.headers_complete) { report["stop_reason"] = "request_error"; break; }
        const bool redirect = response.status == 301 || response.status == 302 || response.status == 303
            || response.status == 307 || response.status == 308;
        if (!redirect) { report["stop_reason"] = "complete"; break; }
        const auto locations = values(response, "location");
        if (locations.size() != 1 || locations.front().empty()) { report["stop_reason"] = "invalid_location"; break; }
        Url next;
        try { next = parse_url(locations.front(), current.value); }
        catch (const std::invalid_argument& error) { hop["redirect_error"] = error.what(); report["stop_reason"] = "invalid_location"; break; }
        hop["redirect_target"] = next.value;
        if (current.scheme == "https" && next.scheme == "http") { report["stop_reason"] = "https_downgrade_blocked"; break; }
        if (!allowed.contains(next.origin)) { report["stop_reason"] = "out_of_scope"; break; }
        if (visited.contains(next.value)) { report["stop_reason"] = "redirect_loop"; break; }
        if (step >= options.max_redirects) { report["stop_reason"] = "redirect_limit"; break; }
        current = next;
    }
    report["finished_at"] = timestamp();
    return report;
}
}
