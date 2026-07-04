#include "core/byte_view.hpp"
#include "core/checksum.hpp"
#include "core/ip.hpp"
#include "core/time.hpp"
#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    packetguard::core::ByteView view(data, size);
    packetguard::core::ByteReader reader(view);
    while (reader.remaining() > 0) {
        switch (reader.offset() % 6) {
            case 0: (void)reader.read_u8(); break;
            case 1: (void)reader.read_be16(); break;
            case 2: (void)reader.read_le16(); break;
            case 3: (void)reader.read_be32(); break;
            case 4: (void)reader.read_le32(); break;
            default: {
                auto n = reader.remaining() > 8 ? 8 : reader.remaining();
                (void)reader.read_bytes(n);
                break;
            }
        }
    }
    std::string text(reinterpret_cast<const char*>(data), reinterpret_cast<const char*>(data + size));
    (void)packetguard::core::parse_ipv4(text);
    (void)packetguard::core::parse_cidr(text);
    (void)packetguard::core::parse_unix_timestamp(text);
    (void)packetguard::core::parse_iso8601_utc(text);
    (void)packetguard::core::internet_checksum(view);
    (void)packetguard::core::crc32(view);
    if (auto ip = packetguard::core::parse_ipv4("192.0.2.10")) {
        (void)packetguard::core::classify_ipv4(*ip);
        (void)packetguard::core::ipv4_to_string(*ip);
        (void)packetguard::core::is_private_ipv4(*ip);
        (void)packetguard::core::is_reserved_ipv4(*ip);
    }
    return 0;
}
