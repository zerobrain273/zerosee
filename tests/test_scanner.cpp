#include "scanner.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>

std::atomic<int> active{0}, peak{0};
std::array<std::atomic<int>, 32> visits{};
bool throw_probe = false;

// Fake probe exercises scheduling without depending on network access or timing benchmarks.
PortResult probe_tcp(const std::string&, std::uint16_t port, int)
{
    if (throw_probe) { throw std::runtime_error("probe failure"); }
    const int current = ++active;
    int previous = peak.load();
    while (current > previous && !peak.compare_exchange_weak(previous, current)) {}
    ++visits.at(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    --active;
    return {PortState::open, 0, port};
}

int main()
{
    ScanOptions options;
    options.target = "127.0.0.1";
    for (std::uint16_t port = 1; port <= 20; ++port) { options.ports.push_back(port); }
    for (const int concurrency : {1, 4, 256}) {
        options.concurrency = concurrency;
        peak = 0;
        for (auto& value : visits) { value = 0; }
        const auto results = scan_ports(options);
        if (results.size() != options.ports.size() || peak > concurrency || active != 0) { return 1; }
        for (std::size_t index = 0; index < results.size(); ++index) {
            const auto port = options.ports[index];
            if (visits[port] != 1 || results[index].elapsed_ms != port) { return 1; }
        }
    }
    throw_probe = true;
    try { scan_ports(options); return 1; }
    catch (const std::runtime_error&) {}
    throw_probe = false;
    options.ports.clear();
    if (!scan_ports(options).empty()) { return 1; }
    options.concurrency = 0;
    try { scan_ports(options); return 1; }
    catch (const std::invalid_argument&) {}
    std::cout << "Concurrency bound, exactly-once results, ordering and exception handling passed\n";
}
