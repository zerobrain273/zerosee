#pragma once

#include <iostream>
#include <array>
#include <cstdlib>
#include <string_view>
#include <unistd.h>

inline void print_banner()
{
    constexpr std::array<std::string_view, 6> z = {
        " _______",
        "|____  /",
        "    / / ",
        "   / /  ",
        "  / /___",
        " /_____/",
    };
    constexpr std::array<std::string_view, 6> rest = {
        R"(  _____  ___  ______)",
        R"( / ____||__ \|  ____|)",
        R"(| (___     ) | |__   )",
        R"( \___ \   / /|  __|  )",
        R"( ____) | / /_| |____ )",
        R"(|_____/ |____|______|)",
    };
    const char* term = std::getenv("TERM");
    const bool color = isatty(STDOUT_FILENO) && !std::getenv("NO_COLOR")
        && term && std::string_view(term) != "dumb";
    for (std::size_t row = 0; row < z.size(); ++row) {
        if (color) { std::cout << "\033[31m"; }
        std::cout << z[row];
        if (color) { std::cout << "\033[39m"; }
        std::cout << rest[row] << '\n';
    }
    std::cout << " Zero See | watch ports, inspect web  " << ZEROSEE_VERSION << "\n\n";
}
