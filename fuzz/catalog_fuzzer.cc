#include "core/security_catalog.hpp"
#include <cstddef>
#include <cstdint>
#include <string>

static std::uint16_t read_port(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[0]) << 8) | data[1]);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string text(reinterpret_cast<const char*>(data), reinterpret_cast<const char*>(data + size));
    auto port = read_port(data, size);
    (void)packetguard::core::lookup_service_profile(port, "tcp");
    (void)packetguard::core::lookup_service_profile(port, "udp");
    (void)packetguard::core::service_exposure_label(port, text);
    (void)packetguard::core::lookup_dns_type_profile(port);
    (void)packetguard::core::dns_type_signal_label(port);
    (void)packetguard::core::lookup_rule_option_profile(text);
    (void)packetguard::core::lookup_policy_setting_profile(text);
    (void)packetguard::core::service_profiles_by_risk(text);
    (void)packetguard::core::service_profiles_by_category(text);
    auto options = packetguard::core::known_rule_options();
    auto settings = packetguard::core::known_policy_settings();
    if (!options.empty()) (void)packetguard::core::lookup_rule_option_profile(options.front().name);
    if (!settings.empty()) (void)packetguard::core::lookup_policy_setting_profile(settings.front().key);
    return 0;
}
