#pragma once

#include <cstdint>
#include <string>

enum class PortState { open, refused, timeout, error };

struct PortResult {
    PortState state;
    int error_number;
    long long elapsed_ms;
};

PortResult probe_tcp(const std::string& target, std::uint16_t port, int timeout_ms);
const char* state_name(PortState state);
