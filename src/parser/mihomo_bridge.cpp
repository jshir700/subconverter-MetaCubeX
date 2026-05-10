#include "mihomo_bridge.h"
#include "param_compat.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>

#ifdef _MSC_VER
// MSVC doesn't support C99 complex macro, use a workaround
#define GO_CGO_LIBIMPORT __declspec(dllimport)
#else
#define GO_CGO_LIBIMPORT
#endif

// Declare the Go functions exported from the bridge library
extern "C" {
GO_CGO_LIBIMPORT char *ConvertSubscription(char *data);
GO_CGO_LIBIMPORT void FreeString(char *s);
}

namespace mihomo {

bool isMihomoParserAvailable() {
    // The parser is available if USE_MIHOMO_PARSER is defined at compile time.
    // We cannot easily check at runtime if the Go library is loaded,
    // so we return true here. The actual availability is determined by the
    // build system linking the Go library.
#ifdef USE_MIHOMO_PARSER
    return true;
#else
    return false;
#endif
}

bool isParamSupported(const std::string &protocol, const std::string &param) {
    auto proto_it = PARAM_COMPAT.find(protocol);
    if (proto_it == PARAM_COMPAT.end())
        return false;
    const auto &params = proto_it->second;
    return params.find(param) != params.end();
}

bool isParamHardcoded(const std::string &protocol, const std::string &param) {
    auto proto_it = PARAM_COMPAT.find(protocol);
    if (proto_it == PARAM_COMPAT.end())
        return false;
    const auto &params = proto_it->second;
    auto param_it = params.find(param);
    if (param_it == params.end())
        return false;
    return param_it->second.hardcoded;
}

static std::string trim(const std::string &str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, last - first + 1);
}

static std::string stripQuotes(const std::string &str) {
    std::string trimmed = trim(str);
    if (trimmed.size() >= 2 &&
        ((trimmed[0] == '"' && trimmed[trimmed.size() - 1] == '"') ||
         (trimmed[0] == '\'' && trimmed[trimmed.size() - 1] == '\''))) {
        return trimmed.substr(1, trimmed.size() - 2);
    }
    return trimmed;
}

static std::string jsonEscape(const std::string &str) {
    std::string result;
    result.reserve(str.size());
    for (char c : str) {
        switch (c) {
        case '"':
            result += "\\\"";
            break;
        case '\\':
            result += "\\\\";
            break;
        case '\b':
            result += "\\b";
            break;
        case '\f':
            result += "\\f";
            break;
        case '\n':
            result += "\\n";
            break;
        case '\r':
            result += "\\r";
            break;
        case '\t':
            result += "\\t";
            break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                result += buf;
            } else {
                result += c;
            }
            break;
        }
    }
    return result;
}

std::vector<ProxyNode> parseSubscription(const std::string &subscription) {
    std::vector<ProxyNode> result;

    if (subscription.empty()) {
        return result;
    }

    // Prepare the data for the Go function
    // Go string must be null-terminated
    char *inputData = strdup(subscription.c_str());
    if (!inputData) {
        throw std::runtime_error("Failed to allocate memory for Go input");
    }

    // Call Go ConvertSubscription
    char *jsonResult = ConvertSubscription(inputData);
    free(inputData);

    if (!jsonResult) {
        throw std::runtime_error(
            "Go ConvertSubscription returned null pointer");
    }

    std::string jsonStr(jsonResult);

    // Free Go-allocated string
    FreeString(jsonResult);

    // Parse JSON result
    // Expected format: [{"name":"...","type":"...","server":"...","port":...,"params":{"key":"value",...}},...]
    if (jsonStr.empty() || jsonStr == "[]" || jsonStr == "null") {
        return result;
    }

    // Simple JSON array parser
    // Find the start of array
    size_t pos = 0;
    while (pos < jsonStr.size() &&
           (jsonStr[pos] == ' ' || jsonStr[pos] == '\t' ||
            jsonStr[pos] == '\n' || jsonStr[pos] == '\r')) {
        pos++;
    }

    if (pos >= jsonStr.size() || jsonStr[pos] != '[') {
        throw std::runtime_error("Invalid JSON: expected '[' at position " +
                                 std::to_string(pos));
    }
    pos++; // skip '['

    // Parse each object in the array
    while (pos < jsonStr.size()) {
        // Skip whitespace and commas
        while (pos < jsonStr.size() &&
               (jsonStr[pos] == ' ' || jsonStr[pos] == '\t' ||
                jsonStr[pos] == '\n' || jsonStr[pos] == '\r' ||
                jsonStr[pos] == ',')) {
            pos++;
        }

        if (pos >= jsonStr.size() || jsonStr[pos] == ']') {
            break;
        }

        if (jsonStr[pos] != '{') {
            throw std::runtime_error(
                "Invalid JSON: expected '{' at position " +
                std::to_string(pos));
        }
        pos++; // skip '{'

        ProxyNode node;

        // Parse key-value pairs
        while (pos < jsonStr.size() && jsonStr[pos] != '}') {
            // Skip whitespace
            while (pos < jsonStr.size() &&
                   (jsonStr[pos] == ' ' || jsonStr[pos] == '\t' ||
                    jsonStr[pos] == '\n' || jsonStr[pos] == '\r' ||
                    jsonStr[pos] == ',')) {
                pos++;
            }

            if (pos >= jsonStr.size() || jsonStr[pos] == '}') {
                break;
            }

            // Parse key
            if (jsonStr[pos] != '"') {
                throw std::runtime_error(
                    "Invalid JSON: expected '\"' for key at position " +
                    std::to_string(pos));
            }
            pos++; // skip opening quote

            std::string key;
            while (pos < jsonStr.size() && jsonStr[pos] != '"') {
                if (jsonStr[pos] == '\\') {
                    pos++;
                    if (pos < jsonStr.size()) {
                        key += jsonStr[pos];
                        pos++;
                    }
                } else {
                    key += jsonStr[pos];
                    pos++;
                }
            }
            if (pos < jsonStr.size()) {
                pos++; // skip closing quote
            }

            // Skip colon
            while (pos < jsonStr.size() &&
                   (jsonStr[pos] == ' ' || jsonStr[pos] == '\t' ||
                    jsonStr[pos] == '\n' || jsonStr[pos] == '\r' ||
                    jsonStr[pos] == ':')) {
                pos++;
            }

            // Parse value
            if (pos >= jsonStr.size()) {
                break;
            }

            if (jsonStr[pos] == '"') {
                // String value
                pos++; // skip opening quote
                std::string value;
                while (pos < jsonStr.size() && jsonStr[pos] != '"') {
                    if (jsonStr[pos] == '\\') {
                        pos++;
                        if (pos < jsonStr.size()) {
                            value += jsonStr[pos];
                            pos++;
                        }
                    } else {
                        value += jsonStr[pos];
                        pos++;
                    }
                }
                if (pos < jsonStr.size()) {
                    pos++; // skip closing quote
                }

                // Assign to the appropriate field
                if (key == "name") {
                    node.name = value;
                } else if (key == "type") {
                    node.type = value;
                } else if (key == "server") {
                    node.server = value;
                } else if (key == "port") {
                    try {
                        node.port =
                            static_cast<uint16_t>(std::stoi(value));
                    } catch (...) {
                        // Ignore parse errors for port
                    }
                } else {
                    node.params[key] = value;
                }
            } else if (jsonStr[pos] == '{' || jsonStr[pos] == '[') {
                // Nested object or array - capture the entire value
                char closingChar = (jsonStr[pos] == '{') ? '}' : ']';
                int depth = 1;
                size_t start = pos;
                pos++;
                while (pos < jsonStr.size() && depth > 0) {
                    if (jsonStr[pos] == '"') {
                        pos++;
                        while (pos < jsonStr.size() &&
                               jsonStr[pos] != '"') {
                            if (jsonStr[pos] == '\\')
                                pos++;
                            pos++;
                        }
                        pos++;
                    } else if (jsonStr[pos] == '{' ||
                               jsonStr[pos] == '[') {
                        depth++;
                        pos++;
                    } else if (jsonStr[pos] == '}' ||
                               jsonStr[pos] == ']') {
                        depth--;
                        pos++;
                    } else {
                        pos++;
                    }
                }
                std::string nestedValue =
                    jsonStr.substr(start, pos - start);
                if (key != "name" && key != "type" && key != "server" &&
                    key != "port") {
                    node.params[key] = nestedValue;
                }
            } else {
                // Number or boolean value
                size_t valStart = pos;
                while (pos < jsonStr.size() &&
                       jsonStr[pos] != ',' && jsonStr[pos] != '}' &&
                       jsonStr[pos] != ']' &&
                       jsonStr[pos] != ' ' && jsonStr[pos] != '\t' &&
                       jsonStr[pos] != '\n' && jsonStr[pos] != '\r') {
                    pos++;
                }
                std::string value =
                    jsonStr.substr(valStart, pos - valStart);

                if (key == "port") {
                    try {
                        node.port = static_cast<uint16_t>(
                            std::stoi(value));
                    } catch (...) {
                    }
                } else if (key != "name" && key != "type" &&
                           key != "server") {
                    node.params[key] = value;
                }
            }
        }

        // Skip to end of object
        if (pos < jsonStr.size() && jsonStr[pos] == '}') {
            pos++; // skip '}'
        }

        result.push_back(node);
    }

    return result;
}

} // namespace mihomo
