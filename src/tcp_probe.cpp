#include "tcp_probe.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
// A single owner closes the descriptor on every return path.
class Socket {
public:
    explicit Socket(int descriptor) : descriptor_(descriptor) {}
    ~Socket() { if (descriptor_ >= 0) { ::close(descriptor_); } }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    int get() const { return descriptor_; }
private:
    int descriptor_;
};
}

const char* state_name(PortState state)
{
    switch (state) {
    case PortState::open: return "OPEN";
    case PortState::refused: return "REFUSED";
    case PortState::timeout: return "TIMEOUT";
    case PortState::error: return "ERROR";
    }
    return "ERROR";
}

PortResult probe_tcp(const std::string& target, std::uint16_t port, int timeout_ms)
{
    using Clock = std::chrono::steady_clock;
    const auto start = Clock::now();
    const auto deadline = start + std::chrono::milliseconds(timeout_ms);
    const auto finish = [&](int error) {
        const auto state = error == 0 ? PortState::open
            : error == ECONNREFUSED ? PortState::refused
            : error == ETIMEDOUT ? PortState::timeout : PortState::error;
        return PortResult{state, error,
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count()};
    };
    if (timeout_ms < 1) { return finish(EINVAL); }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, target.c_str(), &address.sin_addr) != 1) {
        return finish(EINVAL);
    }
    Socket socket(::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    if (socket.get() < 0) { return finish(errno); }
    if (::connect(socket.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0) {
        return finish(0);
    }
    const int connect_error = errno;
    if (connect_error != EINPROGRESS && connect_error != EINTR) {
        return finish(connect_error);
    }
    while (true) {
        const auto now = Clock::now();
        if (now >= deadline) { return finish(ETIMEDOUT); }
        const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count();
        pollfd descriptor{socket.get(), POLLOUT, 0};
        const int ready = ::poll(&descriptor, 1, static_cast<int>(remaining));
        if (ready < 0) {
            const int poll_error = errno;
            if (poll_error == EINTR) { continue; }
            return finish(poll_error);
        }
        if (ready == 0) { continue; }
        if (descriptor.revents & POLLNVAL) { return finish(EBADF); }
        // Writability also occurs on failure; SO_ERROR gives the actual outcome.
        int socket_error = 0;
        socklen_t length = sizeof(socket_error);
        if (::getsockopt(socket.get(), SOL_SOCKET, SO_ERROR, &socket_error, &length) < 0) {
            return finish(errno);
        }
        return finish(socket_error);
    }
}
