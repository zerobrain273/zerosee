#include "tcp_probe.hpp"

#include <cerrno>
#include <chrono>
#include <iostream>
#include <poll.h>
#include <sys/socket.h>
#include <thread>

// Linker wrappers keep these tests deterministic and independent of networking.
enum class Scenario { immediate, refused, pending, timeout, interrupted, socket_error, query_error };
Scenario scenario;
int closed = 0;
int polls = 0;

extern "C" int __wrap_socket(int, int, int)
{
    if (scenario == Scenario::socket_error) { errno = EMFILE; return -1; }
    return 42;
}
extern "C" int __wrap_close(int) { ++closed; return 0; }
extern "C" int __wrap_connect(int, const sockaddr*, socklen_t)
{
    if (scenario == Scenario::immediate) { return 0; }
    errno = EINPROGRESS;
    return -1;
}
extern "C" int __wrap_poll(pollfd* descriptor, nfds_t, int timeout)
{
    ++polls;
    if (scenario == Scenario::timeout || scenario == Scenario::interrupted) {
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
        if (scenario == Scenario::interrupted) { errno = EINTR; return -1; }
        return 0;
    }
    descriptor->revents = POLLOUT;
    return 1;
}
extern "C" int __wrap_getsockopt(int, int, int, void* value, socklen_t*)
{
    if (scenario == Scenario::query_error) { errno = EBADF; return -1; }
    *static_cast<int*>(value) = scenario == Scenario::refused ? ECONNREFUSED : 0;
    return 0;
}

int main()
{
    struct Case { Scenario scenario; PortState expected; int error; int closes; };
    const Case cases[] = {
        {Scenario::immediate, PortState::open, 0, 1},
        {Scenario::pending, PortState::open, 0, 1},
        {Scenario::refused, PortState::refused, ECONNREFUSED, 1},
        {Scenario::timeout, PortState::timeout, ETIMEDOUT, 1},
        {Scenario::interrupted, PortState::timeout, ETIMEDOUT, 1},
        {Scenario::socket_error, PortState::error, EMFILE, 0},
        {Scenario::query_error, PortState::error, EBADF, 1},
    };
    for (const auto& test : cases) {
        scenario = test.scenario;
        closed = polls = 0;
        const auto result = probe_tcp("127.0.0.1", 8000, 5);
        if (result.state != test.expected || result.error_number != test.error
            || closed != test.closes) {
            std::cerr << "Unexpected result or socket lifetime\n";
            return 1;
        }
        if (scenario == Scenario::interrupted && polls != 1) {
            std::cerr << "Interrupted wait reset the deadline\n";
            return 1;
        }
    }
    std::cout << "TCP state, deadline and descriptor ownership checks passed\n";
}
