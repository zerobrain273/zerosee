#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct ScanOptions {
    std::string target;
    std::vector<std::uint16_t> ports;
    int timeout_ms = 1000;
    bool dry_run = false;
    int concurrency = 16;
    bool no_banner = false;
};

// Throws std::invalid_argument when the command does not match our CLI.
ScanOptions parse_scan_arguments(int argc, char* argv[]);
