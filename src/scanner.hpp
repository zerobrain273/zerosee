#pragma once

#include "cli.hpp"
#include "tcp_probe.hpp"

// Results preserve the order of options.ports regardless of completion order.
std::vector<PortResult> scan_ports(const ScanOptions& options);
