#include "scanner.hpp"

#include <algorithm>
#include <atomic>
#include <exception>
#include <mutex>
#include <stdexcept>
#include <thread>

std::vector<PortResult> scan_ports(const ScanOptions& options)
{
    if (options.concurrency < 1 || options.concurrency > 256) {
        throw std::invalid_argument("Concurrency must be between 1 and 256.");
    }
    std::vector<PortResult> results(options.ports.size());
    std::atomic<std::size_t> next{0};
    std::atomic<bool> stop{false};
    std::exception_ptr failure;
    std::mutex failure_mutex;
    const auto count = std::min(options.ports.size(), static_cast<std::size_t>(options.concurrency));
    {
        // Declared last, so workers are joined before any captured data is destroyed.
        std::vector<std::jthread> workers;
        workers.reserve(count);
        try {
            for (std::size_t worker = 0; worker < count; ++worker) {
                workers.emplace_back([&] {
                    try {
                        while (!stop.load()) {
                            const auto index = next.fetch_add(1);
                            if (index >= options.ports.size()) { break; }
                            results[index] = probe_tcp(options.target, options.ports[index], options.timeout_ms);
                        }
                    } catch (...) {
                        std::lock_guard lock(failure_mutex);
                        if (!failure) { failure = std::current_exception(); }
                        stop.store(true);
                    }
                });
            }
        } catch (...) {
            stop.store(true);
            throw;
        }
    }
    if (failure) { std::rethrow_exception(failure); }
    return results;
}
