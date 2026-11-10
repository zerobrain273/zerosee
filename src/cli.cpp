#include "cli.hpp"

#include <arpa/inet.h>
#include <algorithm>
#include <charconv>
#include <stdexcept>
#include <string_view>

namespace {
unsigned int parse_port(std::string_view text)
{
    unsigned int value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size()
        || value == 0 || value > 65535) {
        throw std::invalid_argument("Ports must be integers between 1 and 65535.");
    }
    return value;
}

std::vector<std::uint16_t> parse_ports(std::string_view text)
{
    if (text.empty()) {
        throw std::invalid_argument("The port list must not be empty.");
    }
    // Fixed-size membership table bounds memory even for repeated ranges.
    std::vector<bool> selected(65536, false);
    while (true) {
        const auto comma = text.find(',');
        const auto token = text.substr(0, comma);
        if (token.empty()) {
            throw std::invalid_argument("The port list contains an empty item.");
        }
        const auto dash = token.find('-');
        const auto first = parse_port(token.substr(0, dash));
        const auto last = dash == std::string_view::npos
            ? first : parse_port(token.substr(dash + 1));
        if (first > last) {
            throw std::invalid_argument("Port ranges must be ascending.");
        }
        for (unsigned int port = first; port <= last; ++port) {
            selected[port] = true;
        }
        if (comma == std::string_view::npos) {
            break;
        }
        text.remove_prefix(comma + 1);
    }
    std::vector<std::uint16_t> ports;
    for (unsigned int port = 1; port <= 65535; ++port) {
        if (selected[port]) {
            ports.push_back(static_cast<std::uint16_t>(port));
        }
    }
    return ports;
}
}

ScanOptions parse_scan_arguments(int argc, char* argv[])
{
    if (argc < 2 || std::string_view(argv[1]) != "scan") {
        throw std::invalid_argument("Expected the 'scan' command.");
    }
    if (argc < 3) {
        throw std::invalid_argument("Missing target IPv4 address.");
    }
    ScanOptions options;
    options.target = argv[2];
    in_addr address{};
    if (inet_pton(AF_INET, options.target.c_str(), &address) != 1) {
        throw std::invalid_argument("Target must be an IPv4 address, for example 127.0.0.1.");
    }
    bool ports_seen = false;
    bool timeout_seen = false;
    bool concurrency_seen = false;
    for (int index = 3; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--no-banner") {
            if (options.no_banner) { throw std::invalid_argument("Specify --no-banner only once."); }
            options.no_banner = true;
            continue;
        }
        if (argument == "-c" || argument == "--concurrency") {
            if (concurrency_seen || ++index >= argc) {
                throw std::invalid_argument("Specify --concurrency once with a value.");
            }
            const std::string_view value(argv[index]);
            int count = 0;
            const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), count);
            if (error != std::errc{} || end != value.data() + value.size() || count < 1 || count > 256) {
                throw std::invalid_argument("Concurrency must be an integer between 1 and 256.");
            }
            options.concurrency = count;
            concurrency_seen = true;
            continue;
        }
        if (argument == "--dry-run") {
            if (options.dry_run) {
                throw std::invalid_argument("Specify --dry-run only once.");
            }
            options.dry_run = true;
            continue;
        }
        if (argument == "--timeout-ms" || argument == "-t") {
            if (timeout_seen || ++index >= argc) {
                throw std::invalid_argument("Specify --timeout-ms once with a value.");
            }
            const std::string_view value(argv[index]);
            int timeout = 0;
            const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), timeout);
            if (error != std::errc{} || end != value.data() + value.size()
                || timeout < 1 || timeout > 60000) {
                throw std::invalid_argument("Timeout must be an integer between 1 and 60000 ms.");
            }
            options.timeout_ms = timeout;
            timeout_seen = true;
            continue;
        }
        if (argument != "--ports" && argument != "-p") {
            throw std::invalid_argument("Unknown argument; use --help for usage.");
        }
        if (ports_seen) {
            throw std::invalid_argument("Specify --ports only once.");
        }
        if (++index >= argc) {
            throw std::invalid_argument("Missing value after --ports.");
        }
        options.ports = parse_ports(argv[index]);
        ports_seen = true;
    }
    if (!ports_seen) {
        throw std::invalid_argument("Specify ports with --ports.");
    }
    return options;
}
