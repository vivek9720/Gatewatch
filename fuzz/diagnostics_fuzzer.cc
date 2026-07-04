#include "core/diagnostics.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    packetguard::core::Diagnostics diagnostics;
    std::string text(reinterpret_cast<const char*>(data), reinterpret_cast<const char*>(data + size));
    for (std::size_t i = 0; i < text.size(); i += 7) {
        auto code = text.substr(i, std::min<std::size_t>(6, text.size() - i));
        if (i % 3 == 0) diagnostics.info(code, text, i);
        else if (i % 3 == 1) diagnostics.warn(code, text, i);
        else diagnostics.error(code, text, i);
    }
    (void)diagnostics.has_errors();
    (void)diagnostics.summary();
    (void)diagnostics.entries();
    return 0;
}
