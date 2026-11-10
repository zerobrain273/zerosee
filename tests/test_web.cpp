#include "web.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

using web::Json;
void require(bool condition, const char* message)
{
    if (!condition) { throw std::runtime_error(message); }
}
template<typename F> void rejects(F function)
{
    try { function(); } catch (const std::invalid_argument&) { return; }
    throw std::runtime_error("Expected invalid_argument");
}
web::Response response(const web::Url& url, long status, std::vector<web::Header> headers = {})
{
    web::Response result;
    result.url = url.value;
    result.status = status;
    result.headers_complete = true;
    result.headers = std::move(headers);
    result.tls_state = url.scheme == "https" ? "verified" : "not_applicable";
    return result;
}
bool has(const Json& findings, const std::string& id)
{
    for (const auto& finding : findings) { if (finding.at("id") == id) { return true; } }
    return false;
}
int main()
{
    try {
        const auto url = web::parse_url("https://EXAMPLE.test:443/a#fragment");
        require(url.origin == "https://example.test:443", "Origin canonicalization");
        require(url.value == "https://example.test/a", "URL canonicalization");
        require(web::parse_url("../b", url.value).value == "https://example.test/b", "Relative redirect");
        require(web::parse_url("//other.test/x", url.value).origin == "https://other.test:443", "Protocol relative URL");
        for (const std::string invalid : {"file:///etc/passwd", "http://user:password@example.test/", "example.test", "http://x/a\nb", "http://x\\y/", "http://x:0/"}) {
            rejects([&] { web::parse_url(invalid); });
        }
        web::Options options;
        options.url = "https://example.test/start";
        int calls = 0;
        auto redirect = [&](std::string destination) {
            calls = 0;
            return web::inspect(options, [&](const auto& target, const auto&) {
                ++calls;
                return response(target, 302, {{"Location", destination}});
            });
        };
        require(redirect("https://other.test/")["stop_reason"] == "out_of_scope" && calls == 1, "External redirect must not be fetched");
        require(redirect("https://example.test:444/")["stop_reason"] == "out_of_scope", "Port is part of scope");
        options.allow_origins = {"http://example.test:80"};
        require(redirect("http://example.test/")["stop_reason"] == "https_downgrade_blocked", "Downgrade remains blocked even when allowed");
        require(redirect("/start#different")["stop_reason"] == "redirect_loop", "Fragment-only loop");
        require(redirect("file:///etc/passwd")["stop_reason"] == "invalid_location", "Non-web redirect");
        options.max_redirects = 0;
        require(redirect("/next")["stop_reason"] == "redirect_limit" && calls == 1, "Zero redirect budget");
        options.max_redirects = 5;
        options.allow_origins = {"https://other.test:443"};
        calls = 0;
        const auto allowed = web::inspect(options, [&](const auto& target, const auto&) {
            ++calls;
            if (calls == 1) { return response(target, 301, {{"Location", "https://other.test/"}}); }
            return response(target, 200);
        });
        require(allowed["stop_reason"] == "complete" && calls == 2, "Explicit origin allowed");
        calls = 0;
        const auto loop = web::inspect(options, [&](const auto& target, const auto&) {
            ++calls;
            return response(target, 302, {{"Location", calls == 1 ? "/next" : "/start"}});
        });
        require(loop["stop_reason"] == "redirect_loop" && calls == 2, "Multi-hop loop");
        const auto duplicate = web::inspect(options, [&](const auto& target, const auto&) {
            return response(target, 302, {{"Location", "/one"}, {"Location", "/two"}});
        });
        require(duplicate["stop_reason"] == "invalid_location", "Ambiguous Location");

        auto weak = response(url, 200, {{"Content-Type", "text/html; charset=utf-8"},
            {"Set-Cookie", "session=TOPSECRET; SameSite=None; Path=/"},
            {"Set-Cookie", "__Host-token=SECONDSECRET; Domain=example.test; Secure; Path=/"}});
        const auto cookies = web::cookies(weak);
        require(cookies.size() == 2 && cookies[0]["same_site"] == "none", "Independent cookie parsing");
        require(cookies.dump().find("TOPSECRET") == std::string::npos, "Cookie values must be redacted");
        const auto issues = web::findings(weak);
        require(has(issues, "cookie-none-without-secure") && has(issues, "cookie-prefix-invalid") && has(issues, "csp-missing"), "Weak configuration observations");
        auto strong = response(url, 200, {{"Content-Type", "text/html"}, {"Strict-Transport-Security", "max-age=31536000"},
            {"Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"}, {"X-Content-Type-Options", "nosniff"},
            {"Set-Cookie", "__Host-session=SECRET; Secure; HttpOnly; SameSite=Strict; Path=/"}});
        require(web::findings(strong).empty(), "Strong fixture should not trigger configured rules");
        auto json_response = response(url, 200, {{"Content-Type", "application/json"}});
        require(!has(web::findings(json_response), "csp-missing"), "HTML-only checks must not apply to JSON");
        weak.error = "transfer failed";
        require(web::findings(weak).empty(), "Incomplete response must not create missing-header findings");
        weak.tls_state = "verification_failed";
        require(web::findings(weak).size() == 1 && has(web::findings(weak), "tls-verification-failed"), "TLS failure is separate from missing headers");
        weak.error.clear(); weak.tls_state = "verified";
        auto report = web::inspect(options, [&](const auto&, const auto&) { return weak; });
        require(report.dump().find("TOPSECRET") == std::string::npos, "JSON cookie redaction");
        require(web::markdown(report).find("TOPSECRET") == std::string::npos, "Markdown cookie redaction");
        report["target"] = "<script>evil</script>\x1b[2J";
        const auto rendered = web::markdown(report);
        require(rendered.find("<script>") == std::string::npos && rendered.find('\x1b') == std::string::npos, "Markdown and control escaping");

        web::Capture capture;
        auto line = [&](std::string value) { return web::receive_header(value.data(), 1, value.size(), &capture); };
        line("HTTP/1.1 103 Early Hints\r\n"); line("Link: </a>\r\n"); line("\r\n");
        line("HTTP/1.1 200 OK\r\n"); line("Set-Cookie: a=1\r\n"); line("Set-Cookie: b=2\r\n"); line("\r\n");
        require(capture.response.headers_complete && capture.response.headers.size() == 2, "Final headers replace interim response");
        line("Trailer: ignored\r\n");
        require(capture.response.headers.size() == 2, "Trailers do not become initial headers");
        std::string large(65537, 'x');
        require(web::receive_header(large.data(), 1, large.size(), &capture) == 0 && capture.limit_error, "Header budget");
        web::Capture body;
        require(web::receive_body(large.data(), 1, large.size(), &body) == 0 && body.response.body_truncated, "Body budget");

        char directory[] = "/tmp/zerosee-report-test-XXXXXX";
        require(mkdtemp(directory) != nullptr, "Temporary report directory");
        const auto path = std::string(directory) + "/report.json";
        web::write_new_file(path, "first");
        bool refused = false;
        try { web::write_new_file(path, "second"); } catch (const std::system_error&) { refused = true; }
        require(refused, "Do not overwrite reports");
        std::ifstream input(path); std::string saved; input >> saved;
        require(saved == "first", "Existing report preserved");
        options.json_path = path;
        rejects([&] { web::validate_outputs(options); });
        std::filesystem::remove_all(directory);
        std::cout << "URL/scope, redirects, cookies, TLS findings, reports and response limits passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
