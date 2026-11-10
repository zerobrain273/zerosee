#include <iostream>
#include <stdexcept>
#include <string_view>
#include "cli.hpp"
#include "banner.hpp"
#include "scanner.hpp"
#include "web.hpp"
#include <unistd.h>
#include <system_error>

int main(int argc, char* argv[])
{
    const auto is_help = [](std::string_view value) { return value == "-h" || value == "--help"; };
    bool help = argc == 1;
    if (argc >= 2 && (is_help(argv[1]) || std::string_view(argv[1]) == "scan")) {
        for (int i = 1; i < argc; ++i) { help = help || is_help(argv[i]); }
    }
    if (argc == 2 && (std::string_view(argv[1]) == "--version" || std::string_view(argv[1]) == "-V")) {
        std::cout << "zerosee " << ZEROSEE_VERSION << '\n';
        return 0;
    }
    if (help) {
        print_banner();
        std::cout << "Usage: zerosee scan <IPv4> -p <ports> [options]\n\n"
                  << "Web reconnaissance: zerosee web <http(s)://URL> [options]\n"
                  << "Web help: zerosee web -h\n\n"
                  << "  -h, --help           Show help (also: zerosee scan -h).\n"
                  << "  -V, --version        Show version.\n"
                  << "  -p, --ports LIST     Required: 80,443 or 8000-8010.\n"
                  << "  -t, --timeout-ms N   Per-port timeout, 1-60000 ms (default 1000).\n"
                  << "  -c, --concurrency N  Concurrent checks, 1-256 (default 16).\n"
                  << "      --dry-run       Validate parameters without connecting.\n"
                  << "      --no-banner     Hide the scan banner.\n\n"
                  << "Example: zerosee scan 127.0.0.1 -p 8000-8010 -t 500 -c 4\n"
                  << "TCP connect only; service detection is not implemented yet.\n";
        return 0;
    }
    try {
        if (argc >= 2 && std::string_view(argv[1]) == "web") { return web::run(argc, argv); }
        const auto options = parse_scan_arguments(argc, argv);
        if (isatty(STDOUT_FILENO) && !options.no_banner) {
            print_banner();
        }
        std::cout << "Target: " << options.target << "\nPorts: ";
        for (std::size_t i = 0; i < options.ports.size(); ++i) {
            std::cout << (i == 0 ? "" : ",") << options.ports[i];
        }
        std::cout << "\nTimeout: " << options.timeout_ms << " ms per port\n";
        std::cout << "Concurrency: " << options.concurrency << "\n";
        if (options.dry_run) {
            std::cout << "Dry run: no network connections.\n";
            return 0;
        }
        bool failed = false;
        const auto results = scan_ports(options);
        for (std::size_t index = 0; index < options.ports.size(); ++index) {
            const auto port = options.ports[index];
            const auto& result = results[index];
            std::cout << options.target << ':' << port << "  " << state_name(result.state)
                      << "  " << result.elapsed_ms << " ms";
            if (result.state == PortState::error) {
                std::cout << "  " << std::error_code(result.error_number, std::generic_category()).message()
                          << " (errno=" << result.error_number << ')';
                failed = true;
            }
            std::cout << std::endl;
        }
        return failed ? 1 : 0;
    } catch (const std::invalid_argument& error) {
        std::cerr << "Error: " << error.what() << "\nUse --help for usage.\n";
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "Scan failed: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
