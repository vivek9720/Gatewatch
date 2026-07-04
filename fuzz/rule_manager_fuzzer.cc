#include "rules/rule_set_manager.hpp"
#include "packet/packet.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

static std::vector<std::string> split_ops(const std::string& text) {
    std::vector<std::string> ops;
    std::size_t start = 0;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\n' || text[i] == '\f') {
            ops.push_back(text.substr(start, i - start));
            start = i + 1;
        }
    }
    if (start <= text.size()) ops.push_back(text.substr(start));
    return ops;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string text(reinterpret_cast<const char*>(data), reinterpret_cast<const char*>(data + size));
    packetguard::rules::RuleSetManager manager;
    auto ops = split_ops(text);
    for (std::size_t i = 0; i < ops.size(); ++i) {
        const auto& op = ops[i];
        switch (i % 6) {
            case 0: (void)manager.add_rule_text(op); break;
            case 1: (void)manager.add_rule_file_text(op); break;
            case 2: if (!manager.empty()) (void)manager.replace_rule_text(i % manager.size(), op); break;
            case 3: if (!manager.empty()) (void)manager.erase_index(i % manager.size()); break;
            case 4: (void)manager.erase_sid(static_cast<std::uint32_t>(i)); break;
            default: manager.rebuild_indexes(); break;
        }
        (void)manager.summary();
        (void)manager.snapshot();
        (void)manager.diagnostics().summary();
    }
    packetguard::packet::PacketMetadata metadata;
    metadata.ipv4 = packetguard::packet::IPv4Packet{};
    if (auto src = packetguard::core::parse_ipv4("10.1.2.3")) metadata.ipv4->source = *src;
    if (auto dst = packetguard::core::parse_ipv4("198.51.100.10")) metadata.ipv4->destination = *dst;
    metadata.tcp = packetguard::packet::TcpSegment{};
    metadata.tcp->source_port = 12345;
    metadata.tcp->destination_port = 80;
    (void)manager.match_packet(metadata);
    return 0;
}
