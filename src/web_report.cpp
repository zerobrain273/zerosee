#include "web.hpp"
#include "banner.hpp"

#include <cerrno>
#include <filesystem>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <unistd.h>

namespace web {
std::string safe_text(const std::string& value)
{
    std::ostringstream output;
    for (unsigned char c : value) {
        if (c < 32 || c == 127) {
            output << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        } else { output << static_cast<char>(c); }
    }
    return output.str();
}
namespace {
std::string md(const std::string& value)
{
    std::string result;
    for (char c : safe_text(value)) {
        if (c == '&') { result += "&amp;"; }
        else if (c == '<') { result += "&lt;"; }
        else if (c == '>') { result += "&gt;"; }
        else {
            if (std::string("\\`*_{}[]()#+-.!|").find(c) != std::string::npos) { result += '\\'; }
            result += c;
        }
    }
    return result;
}
}
std::string markdown(const Json& report)
{
    std::ostringstream text;
    text << "# zerosee web reconnaissance\n\n"
         << "Target: " << md(report.at("target").get<std::string>()) << "\n\n"
         << "Started (UTC): " << md(report.at("started_at").get<std::string>()) << "\n\n"
         << "Stop reason: " << md(report.at("stop_reason").get<std::string>()) << "\n\n"
         << "## Scope\n\n";
    for (const auto& origin : report.at("scope")) { text << "- " << md(origin.get<std::string>()) << '\n'; }
    text << "\n## Responses\n";
    for (const auto& hop : report.at("hops")) {
        text << "\n### " << md(hop.at("url").get<std::string>()) << "\n\n"
             << "- HTTP status: " << hop.at("status") << '\n'
             << "- Peer IP: " << md(hop.at("ip").get<std::string>()) << '\n'
             << "- Duration: " << hop.at("elapsed_ms") << " ms\n"
             << "- Headers complete: " << hop.at("headers_complete") << '\n'
             << "- Body truncated: " << hop.at("body_truncated") << '\n'
             << "- TLS: " << md(hop.at("tls").at("state").get<std::string>()) << '\n';
        if (!hop.at("error").get<std::string>().empty()) { text << "- Error: " << md(hop.at("error").get<std::string>()) << '\n'; }
        if (hop.contains("redirect_target")) { text << "- Redirect target: " << md(hop.at("redirect_target").get<std::string>()) << '\n'; }
        text << "\nHeaders:\n\n";
        for (const auto& header : hop.at("headers")) {
            text << "- " << md(header.at("name").get<std::string>()) << ": " << md(header.at("value").get<std::string>()) << '\n';
        }
        text << "\nCookies (values redacted):\n\n";
        for (const auto& cookie : hop.at("cookies")) { text << "- " << md(cookie.dump(-1, ' ', false, Json::error_handler_t::replace)) << '\n'; }
        text << "\nCertificate chain metadata (if supplied by TLS backend):\n\n";
        for (const auto& cert : hop.at("tls").at("certificates")) {
            for (auto item = cert.begin(); item != cert.end(); ++item) {
                text << "- " << md(item.key()) << ": " << md(item.value().get<std::string>()) << '\n';
            }
            text << '\n';
        }
    }
    text << "\n## Observations requiring context\n\n";
    if (report.at("findings").empty()) { text << "No configured rule produced an observation. This does not establish that the target is secure.\n"; }
    for (const auto& finding : report.at("findings")) {
        text << "### " << md(finding.at("id").get<std::string>()) << "\n\n";
        for (const auto& key : {"level", "title", "url", "evidence", "context", "recommendation"}) {
            text << "- " << key << ": " << md(finding.at(key).get<std::string>()) << '\n';
        }
        text << '\n';
    }
    text << "\n## Limitations\n\n";
    for (const auto& value : report.at("limitations")) { text << "- " << md(value.get<std::string>()) << '\n'; }
    return text.str();
}
void validate_outputs(const Options& options)
{
    std::vector<std::filesystem::path> paths;
    for (const auto& value : {options.json_path, options.markdown_path}) {
        if (value.empty()) { continue; }
        const auto path = std::filesystem::absolute(value).lexically_normal();
        if (std::filesystem::exists(path) || std::filesystem::is_symlink(path)) {
            throw std::invalid_argument("Report already exists: " + safe_text(value));
        }
        if (!std::filesystem::is_directory(path.parent_path())) { throw std::invalid_argument("Report parent directory does not exist"); }
        paths.push_back(std::filesystem::weakly_canonical(path));
    }
    if (paths.size() == 2 && paths[0] == paths[1]) { throw std::invalid_argument("JSON and Markdown need different paths"); }
}
void write_new_file(const std::string& path, const std::string& data)
{
    std::string pattern = path + ".tmp.XXXXXX";
    std::vector<char> name(pattern.begin(), pattern.end());
    name.push_back('\0');
    int descriptor = ::mkstemp(name.data());
    if (descriptor < 0) { throw std::system_error(errno, std::generic_category(), "Create report"); }
    try {
        std::size_t offset = 0;
        while (offset < data.size()) {
            const auto count = ::write(descriptor, data.data() + offset, data.size() - offset);
            if (count < 0 && errno == EINTR) { continue; }
            if (count <= 0) { throw std::system_error(count < 0 ? errno : EIO, std::generic_category(), "Write report"); }
            offset += static_cast<std::size_t>(count);
        }
        const auto closed = ::close(descriptor);
        descriptor = -1;
        if (closed != 0) { throw std::system_error(errno, std::generic_category(), "Close report"); }
        // Atomic publish without replacing an existing destination, including symlinks.
        if (::link(name.data(), path.c_str()) != 0) { throw std::system_error(errno, std::generic_category(), "Publish report"); }
        ::unlink(name.data());
    } catch (...) {
        if (descriptor >= 0) { ::close(descriptor); }
        ::unlink(name.data());
        throw;
    }
}
int run(int argc, char* argv[])
{
    for (int i = 2; i < argc; ++i) {
        if (std::string(argv[i]) == "-h" || std::string(argv[i]) == "--help") { std::cout << help(); return 0; }
    }
    const auto options = parse_options(argc, argv);
    if (isatty(STDOUT_FILENO) && !options.no_banner) { print_banner(); }
    const auto report = inspect(options);
    if (!options.json_path.empty()) { write_new_file(options.json_path, report.dump(2, ' ', false, Json::error_handler_t::replace) + '\n'); }
    if (!options.markdown_path.empty()) { write_new_file(options.markdown_path, markdown(report)); }
    for (const auto& hop : report.at("hops")) {
        std::cout << "HTTP " << hop.at("status") << "  " << safe_text(hop.at("url").get<std::string>())
                  << "  " << hop.at("elapsed_ms") << " ms  TLS=" << hop.at("tls").at("state").get<std::string>() << '\n';
        if (!hop.at("error").get<std::string>().empty()) { std::cout << "  Error: " << safe_text(hop.at("error").get<std::string>()) << '\n'; }
        for (const auto& header : hop.at("headers")) {
            std::cout << "  " << safe_text(header.at("name").get<std::string>()) << ": " << safe_text(header.at("value").get<std::string>()) << '\n';
        }
        for (const auto& cookie : hop.at("cookies")) {
            std::cout << "  Cookie: " << safe_text(cookie.dump(-1, ' ', false, Json::error_handler_t::replace)) << '\n';
        }
    }
    for (const auto& finding : report.at("findings")) {
        std::cout << '[' << finding.at("level").get<std::string>() << "] " << finding.at("id").get<std::string>()
                  << ": " << safe_text(finding.at("evidence").get<std::string>()) << '\n';
    }
    const auto reason = report.at("stop_reason").get<std::string>();
    std::cout << "Stop: " << reason << "; observations: " << report.at("findings").size() << '\n';
    if (!options.json_path.empty()) { std::cout << "JSON: " << safe_text(options.json_path) << '\n'; }
    if (!options.markdown_path.empty()) { std::cout << "Markdown: " << safe_text(options.markdown_path) << '\n'; }
    return reason == "complete" || reason == "out_of_scope" || reason == "https_downgrade_blocked" ? 0 : 1;
}
}
