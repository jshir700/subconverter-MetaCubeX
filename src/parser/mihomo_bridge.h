#ifndef MIHOMO_BRIDGE_H_INCLUDED
#define MIHOMO_BRIDGE_H_INCLUDED

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace mihomo {

struct ProxyNode {
    std::string name;
    std::string type;
    std::string server;
    uint16_t port = 0;
    std::map<std::string, std::string> params;
};

// Parse subscription data using the mihomo Go parser bridge.
// Returns a vector of ProxyNode structs.
// Throws std::runtime_error if parsing fails.
std::vector<ProxyNode> parseSubscription(const std::string &subscription);

// Check if the mihomo Go parser is available at runtime.
// Returns true if the Go library was loaded successfully.
bool isMihomoParserAvailable();

// Check if a parameter is supported for a given protocol
bool isParamSupported(const std::string &protocol, const std::string &param);

// Check if a parameter is hardcoded by mihomo (should not be overridden)
bool isParamHardcoded(const std::string &protocol, const std::string &param);

} // namespace mihomo

#endif // MIHOMO_BRIDGE_H_INCLUDED
