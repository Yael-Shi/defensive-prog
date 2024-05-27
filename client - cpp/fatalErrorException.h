#pragma once

#include <stdexcept>
#include <string>

class FatalErrorException : public std::runtime_error {
public:
    FatalErrorException(const std::string& message) : std::runtime_error(message) {}
};