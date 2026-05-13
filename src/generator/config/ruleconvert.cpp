#include <string>
#include <unordered_set>
#include <vector>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <regex>

#include "handler/settings.h"
#include "utils/logger.h"
#include "utils/network.h"
#include "utils/regexp.h"
#include "utils/string.h"
#include "utils/string_hash.h"
#include "utils/urlencode.h"
#include "utils/yamlcpp_extra.h"
#include "utils/rapidjson_extra.h"
#include "subexport.h"

/// rule type lists
#define basic_types "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "SRC-IP-CIDR", "GEOIP", "MATCH", "FINAL"
string_array ClashRuleTypes = {basic_types, "IP-CIDR6", "SRC-PORT", "DST-PORT", "PROCESS-NAME",
    "DOMAIN-REGEX", "DOMAIN-WILDCARD", "GEOSITE", "IP-SUFFIX", "IP-ASN",
    "SRC-GEOIP", "SRC-IP-ASN", "SRC-IP-SUFFIX",
    "IN-PORT", "IN-TYPE", "IN-USER", "IN-NAME",
    "PROCESS-PATH", "PROCESS-PATH-WILDCARD", "PROCESS-PATH-REGEX", "PROCESS-NAME-WILDCARD", "PROCESS-NAME-REGEX", "UID",
    "NETWORK", "DSCP",
    "SUB-RULE", "RULE-SET", "AND", "OR", "NOT"};
string_array Surge2RuleTypes = {basic_types, "IP-CIDR6", "USER-AGENT", "URL-REGEX", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP"};
string_array SurgeRuleTypes = {basic_types, "IP-CIDR6", "USER-AGENT", "URL-REGEX", "AND", "OR", "NOT", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP"};
string_array QuanXRuleTypes = {basic_types, "USER-AGENT", "HOST", "HOST-SUFFIX", "HOST-KEYWORD"};
string_array SurfRuleTypes = {basic_types, "IP-CIDR6", "PROCESS-NAME", "IN-PORT", "DEST-PORT", "SRC-IP"};
string_array SingBoxRuleTypes = {basic_types, "IP-VERSION", "INBOUND", "PROTOCOL", "NETWORK", "GEOSITE", "SRC-GEOIP", "DOMAIN-REGEX", "PROCESS-NAME", "PROCESS-PATH", "PACKAGE-NAME", "PORT", "PORT-RANGE", "SRC-PORT", "SRC-PORT-RANGE", "USER", "USER-ID"};

std::string convertRuleset(const std::string &content, int type)
{
    /// Target: Surge type,pattern[,flag]
    /// Source: QuanX type,pattern[,group]
    ///         Clash payload:\n  - 'ipcidr/domain/classic(Surge-like)'

    std::string output, strLine;

    if(type == RULESET_SURGE)
    {
        // Auto-detect Clash payload format for RULESET_SURGE type
        if(regFind(content, "payload:\\r?\\n"))
            type = RULESET_CLASH_CLASSICAL;
        else
            return content;
    }

    if(regFind(content, "payload:\\r?\\n")) /// Clash
    {
        output = regReplace(regReplace(content, "payload:\\r?\\n", "", true), R"(\s?^\s*-\s+('|"?)(.*)\1$)", "\n$2", true);
        if(type == RULESET_CLASH_CLASSICAL) /// classical type
            return output;
        std::stringstream ss;
        ss << output;
        char delimiter = getLineBreak(output);
        output.clear();
        string_size pos, lineSize;
        while(getline(ss, strLine, delimiter))
        {
            strLine = trim(strLine);
            lineSize = strLine.size();
            if(lineSize && strLine[lineSize - 1] == '\r') //remove line break
                strLine.erase(--lineSize);

            if(strFind(strLine, "//"))
            {
                strLine.erase(strLine.find("//"));
                strLine = trimWhitespace(strLine);
            }

            if(!strLine.empty() && (strLine[0] != ';' && strLine[0] != '#' && !(lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')))
            {
                pos = strLine.find('/');
                if(pos != std::string::npos) /// ipcidr
                {
                    if(isIPv4(strLine.substr(0, pos)))
                        output += "IP-CIDR,";
                    else
                        output += "IP-CIDR6,";
                }
                else
                {
                    if(strLine[0] == '.' || (lineSize >= 2 && strLine[0] == '+' && strLine[1] == '.')) /// suffix
                    {
                        bool keyword_flag = false;
                        while(endsWith(strLine, ".*"))
                        {
                            keyword_flag = true;
                            strLine.erase(strLine.size() - 2);
                        }
                        output += "DOMAIN-";
                        if(keyword_flag)
                            output += "KEYWORD,";
                        else
                            output += "SUFFIX,";
                        strLine.erase(0, 2 - (strLine[0] == '.'));
                    }
                    else
                        output += "DOMAIN,";
                }
            }
            output += strLine;
            output += '\n';
        }
        return output;
    }
    else /// QuanX
    {
        output = regReplace(regReplace(content, "^(?i:host)", "DOMAIN", true), "^(?i:ip6-cidr)", "IP-CIDR6", true); //translate type
        output = regReplace(output, "^((?i:DOMAIN(?:-(?:SUFFIX|KEYWORD))?|IP-CIDR6?|USER-AGENT),)\\s*?(\\S*?)(?:,(?!no-resolve).*?)(,no-resolve)?$", "\\U$1\\E$2${3:-}", true); //remove group
        return output;
    }
}

static std::string getRuleKey(const std::string &rule) {
    string_size pos = rule.find(',');
    if(pos == std::string::npos)
        return rule;
    string_size pos2 = rule.find(',', pos + 1);
    if(pos2 == std::string::npos)
        return rule;
    std::string type = rule.substr(0, pos);
    std::string value = rule.substr(pos + 1, pos2 - pos - 1);

    // IP-CIDR/IP-CIDR6/GEOIP/SRC-IP-CIDR: include no-resolve flag in the dedup key
    if(type == "IP-CIDR" || type == "IP-CIDR6" || type == "GEOIP" || type == "SRC-IP-CIDR") {
        if(rule.find(",no-resolve") != std::string::npos)
            return type + "," + value + ",no-resolve";
        return type + "," + value;
    }

    // AND/OR/NOT/SUB-RULE: everything except the last field (group/policy)
    if(type == "AND" || type == "OR" || type == "NOT" || type == "SUB-RULE") {
        string_size last_comma = rule.rfind(',');
        if(last_comma != std::string::npos && last_comma > pos2)
            return rule.substr(0, last_comma);
        return type + "," + value;
    }

    // Default: TYPE,VALUE only (group/policy is ignored)
    return type + "," + value;
}

// --- Enhanced containment-based dedup ---

// CIDR information for IP range containment
struct CIDRInfo {
    uint32_t addr;      // Network address (host byte order)
    uint8_t prefix;     // Prefix length 0-32
    bool valid;
};

// Parse a CIDR string like "10.0.0.0/8" or a bare IP like "192.168.1.1"
static CIDRInfo parseCIDR(const std::string &str) {
    CIDRInfo info = {0, 0, false};
    string_size slash = str.find('/');
    std::string ipStr;
    if(slash == std::string::npos) {
        ipStr = str;
        info.prefix = 32;
    } else {
        ipStr = str.substr(0, slash);
        std::string prefixStr = str.substr(slash + 1);
        char *end = nullptr;
        long p = strtol(prefixStr.c_str(), &end, 10);
        if(end == prefixStr.c_str() || *end != '\0' || p < 0 || p > 32)
            return info;
        info.prefix = (uint8_t)p;
    }

    // Quick pre-check: is it a valid IPv4 string?
    if(!isIPv4(ipStr))
        return info;

    // Split by dots and parse
    int octets[4] = {0, 0, 0, 0};
    int parsed = sscanf(ipStr.c_str(), "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]);
    if(parsed != 4)
        return info;
    for(int i = 0; i < 4; i++) {
        if(octets[i] < 0 || octets[i] > 255)
            return info;
    }
    info.addr = ((uint32_t)octets[0] << 24) | ((uint32_t)octets[1] << 16) |
                ((uint32_t)octets[2] << 8) | (uint32_t)octets[3];
    // Mask to network address
    if(info.prefix == 0)
        info.addr = 0;
    else
        info.addr &= (0xFFFFFFFFU << (32 - info.prefix));
    info.valid = true;
    return info;
}

// CIDR6 information for IPv6 range containment
struct CIDR6Info {
    uint8_t addr[16];   // IPv6 network address (big-endian)
    uint8_t prefix;     // Prefix length 0-128
    bool valid;
};

// Manual IPv6 address parser (no inet_pton dependency)
// Parses IPv6 addresses like "2620:0:2d0:200::7" into 16 bytes (big-endian)
static bool parseIPv6Address(const std::string &str, uint8_t addr[16]) {
    // Split by '::' (double colon)
    string_size doubleColon = str.find("::");
    
    if(doubleColon == std::string::npos) {
        // Normal case: 8 groups separated by ':'
        std::vector<std::string> groups;
        std::string current;
        for(char c : str) {
            if(c == ':') {
                groups.push_back(current);
                current.clear();
            } else {
                current += c;
            }
        }
        groups.push_back(current);
        
        if(groups.size() != 8)
            return false;
        
        for(int i = 0; i < 8; i++) {
            if(groups[i].empty())
                return false;
            char *end = nullptr;
            unsigned long val = strtoul(groups[i].c_str(), &end, 16);
            if(end != groups[i].c_str() + groups[i].size())
                return false;
            if(val > 0xFFFF)
                return false;
            addr[i * 2] = (uint8_t)(val >> 8);
            addr[i * 2 + 1] = (uint8_t)(val & 0xFF);
        }
        return true;
    } else {
        // Compressed case: "::" or "group::" or "::group" or "group::group"
        std::string left = str.substr(0, doubleColon);
        std::string right = str.substr(doubleColon + 2);
        
        // Parse left part
        std::vector<uint16_t> leftGroups;
        if(!left.empty()) {
            std::string current;
            for(char c : left) {
                if(c == ':') {
                    if(current.empty())
                        return false;
                    char *end = nullptr;
                    unsigned long val = strtoul(current.c_str(), &end, 16);
                    if(end != current.c_str() + current.size() || val > 0xFFFF)
                        return false;
                    leftGroups.push_back((uint16_t)val);
                    current.clear();
                } else {
                    current += c;
                }
            }
            if(current.empty())
                return false;
            char *end = nullptr;
            unsigned long val = strtoul(current.c_str(), &end, 16);
            if(end != current.c_str() + current.size() || val > 0xFFFF)
                return false;
            leftGroups.push_back((uint16_t)val);
        }
        
        // Parse right part
        std::vector<uint16_t> rightGroups;
        if(!right.empty()) {
            std::string current;
            for(char c : right) {
                if(c == ':') {
                    if(current.empty())
                        return false;
                    char *end = nullptr;
                    unsigned long val = strtoul(current.c_str(), &end, 16);
                    if(end != current.c_str() + current.size() || val > 0xFFFF)
                        return false;
                    rightGroups.push_back((uint16_t)val);
                    current.clear();
                } else {
                    current += c;
                }
            }
            if(current.empty())
                return false;
            char *end = nullptr;
            unsigned long val = strtoul(current.c_str(), &end, 16);
            if(end != current.c_str() + current.size() || val > 0xFFFF)
                return false;
            rightGroups.push_back((uint16_t)val);
        }
        
        if(leftGroups.size() + rightGroups.size() > 7)
            return false;
        
        // Combine: left groups + zeros (padding to 8 total groups) + right groups
        int idx = 0;
        for(uint16_t g : leftGroups) {
            addr[idx * 2] = (uint8_t)(g >> 8);
            addr[idx * 2 + 1] = (uint8_t)(g & 0xFF);
            idx++;
        }
        int zeroCount = 8 - (int)(leftGroups.size() + rightGroups.size());
        for(int i = 0; i < zeroCount; i++) {
            addr[idx * 2] = 0;
            addr[idx * 2 + 1] = 0;
            idx++;
        }
        for(uint16_t g : rightGroups) {
            addr[idx * 2] = (uint8_t)(g >> 8);
            addr[idx * 2 + 1] = (uint8_t)(g & 0xFF);
            idx++;
        }
        return true;
    }
}

static CIDR6Info parseCIDR6(const std::string &str) {
    CIDR6Info info = {{{0}}, 0, false};
    string_size slash = str.find('/');
    std::string ipStr;
    if(slash == std::string::npos) {
        ipStr = str;
        info.prefix = 128;
    } else {
        ipStr = str.substr(0, slash);
        std::string prefixStr = str.substr(slash + 1);
        char *end = nullptr;
        long p = strtol(prefixStr.c_str(), &end, 10);
        if(end == prefixStr.c_str() || *end != '\0' || p < 0 || p > 128)
            return info;
        info.prefix = (uint8_t)p;
    }

    if(!parseIPv6Address(ipStr, info.addr))
        return info;

    // Mask to network address
    if(info.prefix < 128) {
        for(int i = 0; i < 16; i++) {
            int bits = (int)info.prefix - i * 8;
            if(bits >= 8) {
                // full byte, keep as-is
            } else if(bits > 0) {
                uint8_t mask = (uint8_t)(0xFF << (8 - bits));
                info.addr[i] &= mask;
            } else {
                info.addr[i] = 0;
            }
        }
    }
    info.valid = true;
    return info;
}

// Check if CIDR 'inner' is contained within CIDR 'outer' (same address family)
// 'inner' is contained if outer's prefix <= inner's prefix AND
// (inner.addr & outer.mask) == outer.addr
static bool isCIDRContained(const CIDRInfo &inner, const CIDRInfo &outer) {
    if(!inner.valid || !outer.valid)
        return false;
    if(outer.prefix > inner.prefix)
        return false;
    // Build outer's mask
    uint32_t mask = outer.prefix == 0 ? 0 : (0xFFFFFFFFU << (32 - outer.prefix));
    return (inner.addr & mask) == outer.addr;
}

static bool isCIDR6Contained(const CIDR6Info &inner, const CIDR6Info &outer) {
    if(!inner.valid || !outer.valid)
        return false;
    if(outer.prefix > inner.prefix)
        return false;
    // Compare the prefix bits
    int full_bytes = outer.prefix / 8;
    int remaining_bits = outer.prefix % 8;
    if(memcmp(inner.addr, outer.addr, full_bytes) != 0)
        return false;
    if(remaining_bits > 0) {
        uint8_t mask = (uint8_t)(0xFF << (8 - remaining_bits));
        if((inner.addr[full_bytes] & mask) != (outer.addr[full_bytes] & mask))
            return false;
    }
    return true;
}

// Convert a DOMAIN-WILDCARD pattern to a regex string
// * matches zero or more characters, ? matches exactly one character
// Returns empty string on failure
static std::string wildcardToRegex(const std::string &pattern) {
    std::string regex;
    regex.reserve(pattern.size() * 2);
    regex += '^';
    for(char c : pattern) {
        switch(c) {
            case '.':
                regex += "\\.";
                break;
            case '*':
                regex += ".*";
                break;
            case '?':
                regex += ".";
                break;
            // Escape regex special chars
            case '^': case '$': case '+': case '|':
            case '(': case ')': case '[': case ']':
            case '{': case '}': case '\\':
                regex += '\\';
                regex += c;
                break;
            default:
                regex += c;
        }
    }
    regex += '$';
    return regex;
}

// Check if a DOMAIN-WILDCARD pattern 'inner' is contained within 'outer'
// i.e., does 'outer' match all domains that 'inner' matches?
static bool isWildcardContained(const std::string &inner, const std::string &outer) {
    // Exact match
    if(inner == outer)
        return true;
    
    // If outer has no wildcards and inner does: check if outer's literal value is
    // a suffix of inner (for case *.google.com containing *.mail.google.com)
    // Convert both to regex and test if inner matches outer's superset
    std::string outerRegex = wildcardToRegex(outer);
    std::string innerRegex = wildcardToRegex(inner);
    if(outerRegex.empty() || innerRegex.empty())
        return false;

    // Practical check: if both have the same suffix structure after wildcards,
    // check suffix containment
    string_size outerStar = outer.rfind('*');
    string_size innerStar = inner.rfind('*');
    
    if(outerStar != std::string::npos && innerStar != std::string::npos) {
        // Both have wildcards - check if outer's suffix after last * is a suffix of inner's
        std::string outerSuffix = outer.substr(outerStar + 1);
        std::string innerSuffix = inner.substr(innerStar + 1);
        if(outerSuffix.size() <= innerSuffix.size()) {
            if(innerSuffix.substr(innerSuffix.size() - outerSuffix.size()) == outerSuffix) {
                return true;
            }
        }
    } else if(outerStar == std::string::npos) {
        // Outer is literal - inner has wildcards
        // Outer can only contain inner if outer is very general
        return false;
    }
    
    // For other cases, use regex matching: if outer's regex matches inner's
    // wildcard-derived literal forms, it's likely a superset
    // Generate a test domain from inner by replacing wildcards
    std::string testDomain = inner;
    for(char &c : testDomain) {
        if(c == '*' || c == '?')
            c = 'a';
    }
    try {
        std::regex outerRe(outerRegex, std::regex::ECMAScript | std::regex::optimize);
        if(std::regex_match(testDomain, outerRe))
            return true;
    } catch(...) {
        return false;
    }
    return false;
}

// Main containment check: is the new rule's matching set completely contained
// within any of the already-seen rules?
static bool isContainedBySeen(const std::string &rule, const std::vector<std::string> &seenRules) {
    // Parse the new rule key (format: TYPE,VALUE or TYPE,VALUE,no-resolve)
    // No GROUP field - the key is already stripped by getRuleKey()
    string_size pos = rule.find(',');
    if(pos == std::string::npos)
        return false;

    std::string newType = rule.substr(0, pos);

    // Skip complex rule types (AND/OR/NOT/SUB-RULE) - containment not applicable
    if(newType == "AND" || newType == "OR" || newType == "NOT" || newType == "SUB-RULE")
        return false;

    // Extract value and no-resolve flag from the payload after TYPE,
    std::string newPayload = rule.substr(pos + 1);
    bool newNoResolve = false;
    std::string newValue = newPayload;

    // Check for trailing ",no-resolve" suffix
    string_size nrPos = std::string::npos;
    if(newPayload.size() >= 11) {
        nrPos = newPayload.rfind(",no-resolve");
        if(nrPos != std::string::npos) {
            newNoResolve = true;
            newValue = newPayload.substr(0, nrPos);
        }
    }

    for(const std::string &seen : seenRules) {
        string_size spos = seen.find(',');
        if(spos == std::string::npos)
            continue;

        std::string seenType = seen.substr(0, spos);

        // Skip complex types
        if(seenType == "AND" || seenType == "OR" || seenType == "NOT" || seenType == "SUB-RULE")
            continue;

        std::string seenPayload = seen.substr(spos + 1);
        bool seenNoResolve = false;
        std::string seenValue = seenPayload;

        // Check for trailing ",no-resolve" suffix in seen entry
        if(seenPayload.size() >= 11) {
            string_size snrPos = seenPayload.rfind(",no-resolve");
            if(snrPos != std::string::npos) {
                seenNoResolve = true;
                seenValue = seenPayload.substr(0, snrPos);
            }
        }

        // ===== DOMAIN-SUFFIX =====
        // DOMAIN-SUFFIX,A contains DOMAIN-SUFFIX,B if B == A or B ends with ".A"
        // DOMAIN-SUFFIX,A contains DOMAIN,B if B == A or B ends with ".A"
        if((seenType == "DOMAIN-SUFFIX") && (newType == "DOMAIN-SUFFIX" || newType == "DOMAIN")) {
            if(newValue == seenValue || endsWith(newValue, "." + seenValue))
                return true;
        }
        // DOMAIN-SUFFIX,A contains DOMAIN-WILDCARD,B if all domains matching B also match A
        // e.g., DOMAIN-SUFFIX,google.com contains DOMAIN-WILDCARD,*.google.com
        // e.g., DOMAIN-SUFFIX,google.com contains DOMAIN-WILDCARD,*.mail.google.com
        // e.g., DOMAIN-SUFFIX,google.com contains DOMAIN-WILDCARD,??.google.com
        if((seenType == "DOMAIN-SUFFIX") && (newType == "DOMAIN-WILDCARD")) {
            std::string wildValue = newValue;
            // Case 1: wildcard starts with "*." — extract the suffix after "*." and check
            // e.g., *.google.com → suffix="google.com", *.mail.google.com → suffix="mail.google.com"
            if(wildValue.size() > 2 && wildValue[0] == '*' && wildValue[1] == '.') {
                std::string wildSuffix = wildValue.substr(2);
                if(wildSuffix == seenValue || endsWith(wildSuffix, "." + seenValue))
                    return true;
            } else {
                // Case 2: Other wildcard patterns (e.g., ?? .google.com, a*.google.com)
                // Extract the fixed domain portion after the last wildcard character
                // and check if it equals seenValue or is a subdomain of seenValue
                string_size firstWild = wildValue.find_first_of("*?");
                if(firstWild != std::string::npos) {
                    string_size dotAfterWild = wildValue.find('.', firstWild);
                    if(dotAfterWild != std::string::npos) {
                        std::string fixedPart = wildValue.substr(dotAfterWild + 1);
                        if(fixedPart == seenValue || endsWith(fixedPart, "." + seenValue))
                            return true;
                    }
                }
            }
        }

        // ===== DOMAIN-KEYWORD =====
        // DOMAIN-KEYWORD,A contains DOMAIN-KEYWORD,B if A is a substring of B
        // DOMAIN-KEYWORD,A contains DOMAIN-SUFFIX,B if A is substring of B
        // DOMAIN-KEYWORD,A contains DOMAIN,B if A is substring of B
        if(seenType == "DOMAIN-KEYWORD" &&
           (newType == "DOMAIN-KEYWORD" || newType == "DOMAIN-SUFFIX" || newType == "DOMAIN")) {
            if(strFind(newValue, seenValue))
                return true;
        }

        // ===== DOMAIN-WILDCARD =====
        if(seenType == "DOMAIN-WILDCARD" && newType == "DOMAIN-WILDCARD") {
            if(isWildcardContained(newValue, seenValue))
                return true;
        }
        // DOMAIN-WILDCARD contains DOMAIN
        if(seenType == "DOMAIN-WILDCARD" && newType == "DOMAIN") {
            std::string wildRegex = wildcardToRegex(seenValue);
            if(!wildRegex.empty()) {
                try {
                    std::regex re(wildRegex, std::regex::ECMAScript | std::regex::optimize);
                    if(std::regex_match(newValue, re))
                        return true;
                } catch(...) {}
            }
        }
        // DOMAIN-WILDCARD contains DOMAIN-SUFFIX
        if(seenType == "DOMAIN-WILDCARD" && newType == "DOMAIN-SUFFIX") {
            std::string wildRegex = wildcardToRegex(seenValue);
            if(!wildRegex.empty()) {
                try {
                    std::regex re(wildRegex, std::regex::ECMAScript | std::regex::optimize);
                    if(std::regex_match(newValue, re))
                        return true;
                    std::string testSub = "a." + newValue;
                    if(std::regex_match(testSub, re))
                        return true;
                } catch(...) {}
            }
        }

        // ===== DOMAIN (exact) =====
        if(seenType == "DOMAIN" && newType == "DOMAIN" && newValue == seenValue)
            return true;

        // ===== DOMAIN-REGEX =====
        if(seenType == "DOMAIN-REGEX" && newType == "DOMAIN-REGEX") {
            if(newValue == seenValue)
                return true;
        }
        if(seenType == "DOMAIN-REGEX" && newType == "DOMAIN") {
            try {
                std::regex re(seenValue, std::regex::ECMAScript | std::regex::optimize);
                if(std::regex_match(newValue, re))
                    return true;
            } catch(...) {}
        }
        if(seenType == "DOMAIN-REGEX" && newType == "DOMAIN-SUFFIX") {
            try {
                std::regex re(seenValue, std::regex::ECMAScript | std::regex::optimize);
                if(std::regex_match(newValue, re))
                    return true;
                std::string testSub = "a." + newValue;
                if(std::regex_match(testSub, re))
                    return true;
            } catch(...) {}
        }

        // ===== IP-CIDR =====
        if(seenType == "IP-CIDR" && newType == "IP-CIDR" && seenNoResolve == newNoResolve) {
            CIDRInfo inner = parseCIDR(newValue);
            CIDRInfo outer = parseCIDR(seenValue);
            if(isCIDRContained(inner, outer))
                return true;
        }
        // IP-CIDR (seen) contains IP-CIDR6 (new): parse new as CIDR; if IPv4-mapped, check containment
        if(seenType == "IP-CIDR" && newType == "IP-CIDR6" && seenNoResolve == newNoResolve) {
            CIDRInfo outer = parseCIDR(seenValue);
            if(outer.valid) {
                // Try IPv4-mapped IPv6 (::ffff:x.x.x.x) or IPv4-compatible IPv6 (::x.x.x.x)
                CIDR6Info inner6 = parseCIDR6(newValue);
                if(inner6.valid) {
                    // Check if IPv6 address is IPv4-mapped (::ffff:0:0/96) or IPv4-compatible (::/96)
                    // IPv4-mapped: ::ffff:a.b.c.d → prefix >= 96 and bytes 10-11 are 0xff 0xff
                    // IPv4-compatible: ::a.b.c.d → prefix >= 96 and bytes 0-11 are all zero
                    if(inner6.prefix >= 96) {
                        bool isMapped = (inner6.addr[10] == 0xff && inner6.addr[11] == 0xff);
                        bool isCompatible = true;
                        for(int i = 0; i < 12; i++) {
                            if(inner6.addr[i] != 0) { isCompatible = false; break; }
                        }
                        if(isMapped || isCompatible) {
                            // Extract embedded IPv4 from bytes 12-15
                            uint32_t ipv4 = ((uint32_t)inner6.addr[12] << 24) |
                                            ((uint32_t)inner6.addr[13] << 16) |
                                            ((uint32_t)inner6.addr[14] << 8) |
                                            (uint32_t)inner6.addr[15];
                            CIDRInfo inner = {ipv4, 32, true};
                            // Apply inner prefix mask
                            if(inner6.prefix > 96) {
                                uint8_t extraBits = inner6.prefix - 96;
                                if(extraBits < 32) {
                                    inner.prefix = extraBits;
                                    uint32_t mask = (0xFFFFFFFFU << (32 - extraBits));
                                    inner.addr &= mask;
                                }
                            }
                            if(isCIDRContained(inner, outer))
                                return true;
                        }
                    }
                }
            }
        }


        // ===== IP-CIDR6 =====
        if(seenType == "IP-CIDR6" && newType == "IP-CIDR6" && seenNoResolve == newNoResolve) {
            CIDR6Info inner = parseCIDR6(newValue);
            CIDR6Info outer = parseCIDR6(seenValue);
            if(isCIDR6Contained(inner, outer))
                return true;
        }
        // IP-CIDR6 (seen) contains IP-CIDR (new): see if new value can be embedded into seen's IPv4-mapped range
        if(seenType == "IP-CIDR6" && newType == "IP-CIDR" && seenNoResolve == newNoResolve) {
            CIDRInfo inner = parseCIDR(newValue);
            if(inner.valid) {
                // Embed the IPv4 into IPv4-mapped format
                CIDR6Info outer = parseCIDR6(seenValue);
                if(outer.valid && outer.prefix >= 96) {
                    // Build IPv4-mapped address from inner IPv4
                    uint8_t inner6Addr[16] = {0};
                    // ::ffff:
                    inner6Addr[10] = 0xff;
                    inner6Addr[11] = 0xff;
                    // embedded IPv4
                    inner6Addr[12] = (uint8_t)(inner.addr >> 24);
                    inner6Addr[13] = (uint8_t)(inner.addr >> 16);
                    inner6Addr[14] = (uint8_t)(inner.addr >> 8);
                    inner6Addr[15] = (uint8_t)(inner.addr);
                    uint8_t innerPrefix = 96 + inner.prefix;
                    if(innerPrefix > 128) innerPrefix = 128;
                    CIDR6Info inner6 = {{{0}}, innerPrefix, true};
                    memcpy(inner6.addr, inner6Addr, 16);
                    // Mask inner6 to its prefix
                    if(inner6.prefix < 128) {
                        for(int i = 0; i < 16; i++) {
                            int bits = (int)inner6.prefix - i * 8;
                            if(bits > 0 && bits < 8) {
                                uint8_t mask = (uint8_t)(0xFF << (8 - bits));
                                inner6.addr[i] &= mask;
                            } else if(bits <= 0) {
                                inner6.addr[i] = 0;
                            }
                        }
                    }
                    if(isCIDR6Contained(inner6, outer))
                        return true;
                }
            }
        }

        // ===== GEOIP (exact match + no-resolve awareness) =====
        if(seenType == "GEOIP" && newType == "GEOIP" && newValue == seenValue && seenNoResolve == newNoResolve)
            return true;

        // ===== SRC-IP-CIDR =====
        if(seenType == "SRC-IP-CIDR" && newType == "SRC-IP-CIDR" && seenNoResolve == newNoResolve) {
            CIDRInfo inner = parseCIDR(newValue);
            CIDRInfo outer = parseCIDR(seenValue);
            if(isCIDRContained(inner, outer))
                return true;
        }
    }

    return false;
}

// Public wrapper for containment-based dedup (used by /getruleset endpoint)
bool containmentCheck(const std::string &newKey, const std::vector<std::string> &seenKeys) {
    return isContainedBySeen(newKey, seenKeys);
}

static std::string transformRuleToCommon(string_view_array &temp, const std::string &input, const std::string &group, bool no_resolve_only = false)
{
    temp.clear();
    std::string strLine;
    split(temp, input, ',');
    if(temp.size() < 2)
    {
        strLine = temp[0];
        strLine += ",";
        strLine += group;
    }
    else
    {
        strLine = temp[0];
        strLine += ",";
        strLine += temp[1];
        strLine += ",";
        strLine += group;
        if(temp.size() > 2 && (!no_resolve_only || temp[2] == "no-resolve"))
        {
            strLine += ",";
            strLine += temp[2];
        }
    }
    return strLine;
}

void rulesetToClash(YAML::Node &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules, bool new_field_name, bool dedup)
{
    string_array allRules;
    std::string rule_group, retrieved_rules, strLine;
    std::stringstream strStrm;
    const std::string field_name = new_field_name ? "rules" : "Rule";
    YAML::Node rules;
    size_t total_rules = 0;
    // Use vector instead of unordered_set for containment-based dedup
    std::vector<std::string> seenRules;

    if(dedup && !overwrite_original_rules && base_rule[field_name].IsDefined())
    {
        rules = base_rule[field_name];
        for(size_t i = 0; i < rules.size(); i++)
            seenRules.emplace_back(getRuleKey(safe_as<std::string>(rules[i])));
    }

    std::vector<std::string_view> temp(4);
    for(RulesetContent &x : ruleset_content_array)
    {
        if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
            break;
        rule_group = x.rule_group;
        retrieved_rules = x.rule_content.get();
        if(retrieved_rules.empty())
        {
            writeLog(0, "Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!", LOG_LEVEL_WARNING);
            continue;
        }
        if(startsWith(retrieved_rules, "[]"))
        {
            strLine = retrieved_rules.substr(2);
            if(startsWith(strLine, "FINAL"))
                strLine.replace(0, 5, "MATCH");
            strLine = transformRuleToCommon(temp, strLine, rule_group);
            if(dedup)
            {
                std::string key = getRuleKey(strLine);
                if(isContainedBySeen(key, seenRules))
                {
                    total_rules++;
                    continue;
                }
                seenRules.emplace_back(std::move(key));
            }
            allRules.emplace_back(strLine);
            total_rules++;
            continue;
        }
        retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
        char delimiter = getLineBreak(retrieved_rules);

        strStrm.clear();
        strStrm<<retrieved_rules;
        std::string::size_type lineSize;
        while(getline(strStrm, strLine, delimiter))
        {
            if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
                break;
            strLine = trimWhitespace(strLine, true, true); //remove whitespaces
            lineSize = strLine.size();
            if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                continue;
            if(std::none_of(ClashRuleTypes.begin(), ClashRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                continue;
            if(strFind(strLine, "//"))
            {
                strLine.erase(strLine.find("//"));
                strLine = trimWhitespace(strLine);
            }
            strLine = transformRuleToCommon(temp, strLine, rule_group);
            if(dedup)
            {
                std::string key = getRuleKey(strLine);
                if(isContainedBySeen(key, seenRules))
                    continue;
                seenRules.emplace_back(std::move(key));
            }
            allRules.emplace_back(strLine);
        }
    }

    for(std::string &x : allRules)
    {
        rules.push_back(x);
    }

    base_rule[field_name] = rules;
}

std::string rulesetToClashStr(YAML::Node &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules, bool new_field_name, bool dedup)
{
    std::string rule_group, retrieved_rules, strLine, rule_name;
    std::stringstream strStrm;
    const std::string field_name = new_field_name ? "rules" : "Rule";
    std::string output_content = "\n" + field_name + ":\n";
    size_t total_rules = 0;
    string_array provider_names; // track used rule-provider names for collision avoidance
    // Use vector instead of unordered_set for containment-based dedup
    std::vector<std::string> seenRules;

    if(!overwrite_original_rules && base_rule[field_name].IsDefined())
    {
        for(size_t i = 0; i < base_rule[field_name].size(); i++)
        {
            std::string origRule = safe_as<std::string>(base_rule[field_name][i]);
            if(dedup)
                seenRules.emplace_back(getRuleKey(origRule));
            output_content += "  - " + origRule + "\n";
        }
    }
    base_rule.remove(field_name);

    string_view_array temp(4);
    for(RulesetContent &x : ruleset_content_array)
    {
        if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
            break;
        rule_group = x.rule_group;

        // Handle provider mode for Clash-native rulesets with remote URLs
        if(x.provider && !x.rule_path.empty() &&
           (x.rule_type == RULESET_CLASH_DOMAIN || x.rule_type == RULESET_CLASH_IPCIDR || x.rule_type == RULESET_CLASH_CLASSICAL))
        {
            // Extract provider name from URL path (same logic as findFileName in templates.cpp)
            string_size pos = x.rule_path.rfind('/');
            if(pos == std::string::npos)
            {
                pos = x.rule_path.rfind('\\');
                if(pos == std::string::npos)
                    pos = 0;
            }
            string_size pos2 = x.rule_path.rfind('.');
            if(pos2 < pos || pos2 == std::string::npos)
                pos2 = x.rule_path.size();
            rule_name = urlDecode(x.rule_path.substr(pos + 1, pos2 - pos - 1));
            // Handle name collision
            {
                std::string old_rule_name = rule_name;
                int idx = 2;
                while(std::find(provider_names.begin(), provider_names.end(), rule_name) != provider_names.end())
                    rule_name = old_rule_name + " " + std::to_string(idx++);
            }
            provider_names.emplace_back(rule_name);

            // Determine rule-provider behavior from ruleset type
            std::string behavior;
            switch(x.rule_type)
            {
            case RULESET_CLASH_DOMAIN:
                behavior = "domain";
                break;
            case RULESET_CLASH_IPCIDR:
                behavior = "ipcidr";
                break;
            default:
                behavior = "classical";
                break;
            }

            // Generate RULE-SET entry (client-side fetch via rule-provider)
            output_content += "  - RULE-SET," + rule_name + "," + rule_group + "\n";

            // Build rule-provider YAML definition on base_rule
            base_rule["rule-providers"][rule_name]["type"] = "http";
            base_rule["rule-providers"][rule_name]["behavior"] = behavior;
            base_rule["rule-providers"][rule_name]["url"] = x.rule_path;
            base_rule["rule-providers"][rule_name]["path"] = "./providers/" + std::to_string(hash_(x.rule_path)) + ".yaml";
            if(x.update_interval > 0)
                base_rule["rule-providers"][rule_name]["interval"] = x.update_interval;
            if(!x.user_agent.empty())
                base_rule["rule-providers"][rule_name]["header"]["User-Agent"].push_back(make_yaml_quoted_scalar(x.user_agent));
            if(!x.proxy.empty())
                base_rule["rule-providers"][rule_name]["proxy"] = x.proxy;

            total_rules++;
            continue;
        }

        // Original inline expansion logic (unchanged)
        retrieved_rules = x.rule_content.get();
        if(retrieved_rules.empty())
        {
            writeLog(0, "Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!", LOG_LEVEL_WARNING);
            continue;
        }
        if(startsWith(retrieved_rules, "[]"))
        {
            strLine = retrieved_rules.substr(2);
            if(startsWith(strLine, "FINAL"))
                strLine.replace(0, 5, "MATCH");
            strLine = transformRuleToCommon(temp, strLine, rule_group);
            if(dedup)
            {
                std::string key = getRuleKey(strLine);
                if(isContainedBySeen(key, seenRules))
                {
                    total_rules++;
                    continue;
                }
                seenRules.emplace_back(std::move(key));
            }
            output_content += "  - " + strLine + "\n";
            total_rules++;
            continue;
        }
        retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
        char delimiter = getLineBreak(retrieved_rules);

        strStrm.clear();
        strStrm<<retrieved_rules;
        std::string::size_type lineSize;
        while(getline(strStrm, strLine, delimiter))
        {
            if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
                break;
            strLine = trimWhitespace(strLine, true, true); //remove whitespaces
            lineSize = strLine.size();
            if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                continue;
            if(std::none_of(ClashRuleTypes.begin(), ClashRuleTypes.end(), [strLine](const std::string& type){ return startsWith(strLine, type); }))
                continue;
            if(strFind(strLine, "//"))
            {
                strLine.erase(strLine.find("//"));
                strLine = trimWhitespace(strLine);
            }
            strLine = transformRuleToCommon(temp, strLine, rule_group);
            if(dedup)
            {
                std::string key = getRuleKey(strLine);
                if(isContainedBySeen(key, seenRules))
                    continue;
                seenRules.emplace_back(std::move(key));
            }
            output_content += "  - " + strLine + "\n";
            total_rules++;
        }
    }
    return output_content;
}

void rulesetToSurge(INIReader &base_rule, std::vector<RulesetContent> &ruleset_content_array, int surge_ver, bool overwrite_original_rules, const std::string &remote_path_prefix)
{
    string_array allRules;
    std::string rule_group, rule_path, rule_path_typed, retrieved_rules, strLine;
    std::stringstream strStrm;
    size_t total_rules = 0;

    switch(surge_ver) //other version: -3 for Surfboard, -4 for Loon
    {
    case 0:
        base_rule.set_current_section("RoutingRule"); //Mellow
        break;
    case -1:
        base_rule.set_current_section("filter_local"); //Quantumult X
        break;
    case -2:
        base_rule.set_current_section("TCP"); //Quantumult
        break;
    default:
        base_rule.set_current_section("Rule");
    }

    if(overwrite_original_rules)
    {
        base_rule.erase_section();
        switch(surge_ver)
        {
        case -1:
            base_rule.erase_section("filter_remote");
            break;
        case -4:
            base_rule.erase_section("Remote Rule");
            break;
        default:
            break;
        }
    }

    const std::string rule_match_regex = "^(.*?,.*?)(,.*)(,.*)$";

    string_view_array temp(4);
    for(RulesetContent &x : ruleset_content_array)
    {
        if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
            break;
        rule_group = x.rule_group;
        rule_path = x.rule_path;
        rule_path_typed = x.rule_path_typed;
        if(rule_path.empty())
        {
            strLine = x.rule_content.get().substr(2);
            if(strLine == "MATCH")
                strLine = "FINAL";
            if(surge_ver == -1 || surge_ver == -2)
            {
                strLine = transformRuleToCommon(temp, strLine, rule_group, true);
            }
            else
            {
                if(!startsWith(strLine, "AND") && !startsWith(strLine, "OR") && !startsWith(strLine, "NOT"))
                    strLine = transformRuleToCommon(temp, strLine, rule_group);
            }
            strLine = replaceAllDistinct(strLine, ",,", ",");
            allRules.emplace_back(strLine);
            total_rules++;
            continue;
        }
        else
        {
            if(surge_ver == -1 && x.rule_type == RULESET_QUANX && isLink(rule_path))
            {
                strLine = rule_path + ", tag=" + rule_group + ", force-policy=" + rule_group + ", enabled=true";
                base_rule.set("filter_remote", "{NONAME}", strLine);
                continue;
            }
            if(fileExist(rule_path))
            {
                if(surge_ver > 2 && !remote_path_prefix.empty())
                {
                    strLine = "RULE-SET," + remote_path_prefix + "/getruleset?type=1&url=" + urlSafeBase64Encode(rule_path_typed) + "," + rule_group;
                    if(x.update_interval)
                        strLine += ",update-interval=" + std::to_string(x.update_interval);
                    allRules.emplace_back(strLine);
                    continue;
                }
                else if(surge_ver == -1 && !remote_path_prefix.empty())
                {
                    strLine = remote_path_prefix + "/getruleset?type=2&url=" + urlSafeBase64Encode(rule_path_typed) + "&group=" + urlSafeBase64Encode(rule_group);
                    strLine += ", tag=" + rule_group + ", enabled=true";
                    base_rule.set("filter_remote", "{NONAME}", strLine);
                    continue;
                }
                else if(surge_ver == -4 && !remote_path_prefix.empty())
                {
                    strLine = remote_path_prefix + "/getruleset?type=1&url=" + urlSafeBase64Encode(rule_path_typed) + "," + rule_group;
                    base_rule.set("Remote Rule", "{NONAME}", strLine);
                    continue;
                }
            }
            else if(isLink(rule_path))
            {
                if(surge_ver > 2)
                {
                    if(x.rule_type != RULESET_SURGE)
                    {
                        if(!remote_path_prefix.empty())
                            strLine = "RULE-SET," + remote_path_prefix + "/getruleset?type=1&url=" + urlSafeBase64Encode(rule_path_typed) + "," + rule_group;
                        else
                            continue;
                    }
                    else
                        strLine = "RULE-SET," + rule_path + "," + rule_group;

                    if(x.update_interval)
                        strLine += ",update-interval=" + std::to_string(x.update_interval);

                    allRules.emplace_back(strLine);
                    continue;
                }
                else if(surge_ver == -1 && !remote_path_prefix.empty())
                {
                    strLine = remote_path_prefix + "/getruleset?type=2&url=" + urlSafeBase64Encode(rule_path_typed) + "&group=" + urlSafeBase64Encode(rule_group);
                    strLine += ", tag=" + rule_group + ", enabled=true";
                    base_rule.set("filter_remote", "{NONAME}", strLine);
                    continue;
                }
                else if(surge_ver == -4)
                {
                    strLine = rule_path + "," + rule_group;
                    base_rule.set("Remote Rule", "{NONAME}", strLine);
                    continue;
                }
            }
            else
                continue;
            retrieved_rules = x.rule_content.get();
            if(retrieved_rules.empty())
            {
                writeLog(0, "Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!", LOG_LEVEL_WARNING);
                continue;
            }

            retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
            char delimiter = getLineBreak(retrieved_rules);

            strStrm.clear();
            strStrm<<retrieved_rules;
            std::string::size_type lineSize;
            while(getline(strStrm, strLine, delimiter))
            {
                if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
                    break;
                strLine = trimWhitespace(strLine, true, true);
                lineSize = strLine.size();
                if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                    continue;

                /// remove unsupported types
                switch(surge_ver)
                {
                case -2:
                    if(startsWith(strLine, "IP-CIDR6"))
                        continue;
                    [[fallthrough]];
                case -1:
                    if(!std::any_of(QuanXRuleTypes.begin(), QuanXRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                        continue;
                    break;
                case -3:
                    if(!std::any_of(SurfRuleTypes.begin(), SurfRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                        continue;
                    break;
                default:
                    if(surge_ver > 2)
                    {
                        if(!std::any_of(SurgeRuleTypes.begin(), SurgeRuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                            continue;
                    }
                    else
                    {
                        if(!std::any_of(Surge2RuleTypes.begin(), Surge2RuleTypes.end(), [strLine](const std::string& type){return startsWith(strLine, type);}))
                            continue;
                    }
                }

                if(strFind(strLine, "//"))
                {
                    strLine.erase(strLine.find("//"));
                    strLine = trimWhitespace(strLine);
                }

                if(surge_ver == -1 || surge_ver == -2)
                {
                    if(startsWith(strLine, "IP-CIDR6"))
                        strLine.replace(0, 8, "IP6-CIDR");
                    strLine = transformRuleToCommon(temp, strLine, rule_group, true);
                }
                else
                {
                    if(!startsWith(strLine, "AND") && !startsWith(strLine, "OR") && !startsWith(strLine, "NOT"))
                        strLine = transformRuleToCommon(temp, strLine, rule_group);
                }
                allRules.emplace_back(strLine);
                total_rules++;
            }
        }
    }

    for(std::string &x : allRules)
    {
        base_rule.set("{NONAME}", x);
    }
}

static rapidjson::Value transformRuleToSingBox(std::vector<std::string_view> &args, const std::string& rule, const std::string &group, rapidjson::MemoryPoolAllocator<>& allocator)
{
    args.clear();
    split(args, rule, ',');
    if (args.size() < 2) return rapidjson::Value(rapidjson::kObjectType);
    auto type = toLower(std::string(args[0]));
    auto value = toLower(std::string(args[1]));
//    std::string_view option;
//    if (args.size() >= 3) option = args[2];

    rapidjson::Value rule_obj(rapidjson::kObjectType);
    type = replaceAllDistinct(type, "-", "_");
    type = replaceAllDistinct(type, "ip_cidr6", "ip_cidr");
    type = replaceAllDistinct(type, "src_", "source_");
    if (type == "match" || type == "final")
    {
        rule_obj.AddMember("outbound", rapidjson::Value(value.data(), value.size(), allocator), allocator);
    }
    else
    {
        rule_obj.AddMember(rapidjson::Value(type.c_str(), allocator), rapidjson::Value(value.data(), value.size(), allocator), allocator);
        rule_obj.AddMember("outbound", rapidjson::Value(group.c_str(), allocator), allocator);
    }
    return rule_obj;
}

static void appendSingBoxRule(std::vector<std::string_view> &args, rapidjson::Value &rules, const std::string& rule, rapidjson::MemoryPoolAllocator<>& allocator)
{
    using namespace rapidjson_ext;
    args.clear();
    split(args, rule, ',');
    if (args.size() < 2) return;
    auto type = args[0];
//    std::string_view option;
//    if (args.size() >= 3) option = args[2];

    if (none_of(SingBoxRuleTypes, [&](const std::string& t){ return type == t; }))
        return;

    auto realType = toLower(std::string(type));
    auto value = toLower(std::string(args[1]));
    realType = replaceAllDistinct(realType, "-", "_");
    realType = replaceAllDistinct(realType, "ip_cidr6", "ip_cidr");

    rules | AppendToArray(realType.c_str(), rapidjson::Value(value.c_str(), value.size(), allocator), allocator);
}

void rulesetToSingBox(rapidjson::Document &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules)
{
    using namespace rapidjson_ext;
    std::string rule_group, retrieved_rules, strLine, final;
    std::stringstream strStrm;
    size_t total_rules = 0;
    auto &allocator = base_rule.GetAllocator();

    rapidjson::Value rules(rapidjson::kArrayType);
    if (!overwrite_original_rules)
    {
        if (base_rule.HasMember("route") && base_rule["route"].HasMember("rules") && base_rule["route"]["rules"].IsArray())
            rules.Swap(base_rule["route"]["rules"]);
    }

    auto dns_object = buildObject(allocator, "protocol", "dns", "outbound", "dns-out");
    rules.PushBack(dns_object, allocator);

    if (global.singBoxAddClashModes)
    {
        auto global_object = buildObject(allocator, "clash_mode", "Global", "outbound", "GLOBAL");
        auto direct_object = buildObject(allocator, "clash_mode", "Direct", "outbound", "DIRECT");
        rules.PushBack(global_object, allocator);
        rules.PushBack(direct_object, allocator);
    }

    std::vector<std::string_view> temp(4);
    for(RulesetContent &x : ruleset_content_array)
    {
        if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
            break;
        rule_group = x.rule_group;
        retrieved_rules = x.rule_content.get();
        if(retrieved_rules.empty())
        {
            writeLog(0, "Failed to fetch ruleset or ruleset is empty: '" + x.rule_path + "'!", LOG_LEVEL_WARNING);
            continue;
        }
        if(startsWith(retrieved_rules, "[]"))
        {
            strLine = retrieved_rules.substr(2);
            if(startsWith(strLine, "FINAL") || startsWith(strLine, "MATCH"))
            {
                final = rule_group;
                continue;
            }
            rules.PushBack(transformRuleToSingBox(temp, strLine, rule_group, allocator), allocator);
            total_rules++;
            continue;
        }
        retrieved_rules = convertRuleset(retrieved_rules, x.rule_type);
        char delimiter = getLineBreak(retrieved_rules);

        strStrm.clear();
        strStrm<<retrieved_rules;

        std::string::size_type lineSize;
        rapidjson::Value rule(rapidjson::kObjectType);

        while(getline(strStrm, strLine, delimiter))
        {
            if(global.maxAllowedRules && total_rules > global.maxAllowedRules)
                break;
            strLine = trimWhitespace(strLine, true, true); //remove whitespaces
            lineSize = strLine.size();
            if(!lineSize || strLine[0] == ';' || strLine[0] == '#' || (lineSize >= 2 && strLine[0] == '/' && strLine[1] == '/')) //empty lines and comments are ignored
                continue;
            if(strFind(strLine, "//"))
            {
                strLine.erase(strLine.find("//"));
                strLine = trimWhitespace(strLine);
            }
            appendSingBoxRule(temp, rule, strLine, allocator);
        }
        if (rule.ObjectEmpty()) continue;
        rule.AddMember("outbound", rapidjson::Value(rule_group.c_str(), allocator), allocator);
        rules.PushBack(rule, allocator);
    }

    if (!base_rule.HasMember("route"))
        base_rule.AddMember("route", rapidjson::Value(rapidjson::kObjectType), allocator);

    auto finalValue = rapidjson::Value(final.c_str(), allocator);
    base_rule["route"]
    | AddMemberOrReplace("rules", rules, allocator)
    | AddMemberOrReplace("final", finalValue, allocator);
}
