#include <string>
#include <string_view>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <memory>
#include <queue>
#include <deque>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <climits>
#include <array>

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

    // Use string_view to avoid heap allocations from substr()
    std::string_view typeView(rule.data(), pos);
    std::string_view valueView(rule.data() + pos + 1, pos2 - pos - 1);

    // IP-CIDR/IP-CIDR6/GEOIP/SRC-IP-CIDR: include no-resolve flag in the dedup key
    if(typeView == "IP-CIDR" || typeView == "IP-CIDR6" || typeView == "GEOIP" || typeView == "SRC-IP-CIDR") {
        std::string result;
        result.reserve(typeView.size() + 1 + valueView.size() + 10); // +10 for ",no-resolve"
        result.append(typeView.data(), typeView.size());
        result += ',';
        result.append(valueView.data(), valueView.size());
        if(rule.find(",no-resolve") != std::string::npos)
            result.append(",no-resolve", 11);
        return result;
    }

    // AND/OR/NOT/SUB-RULE: everything except the last field (group/policy)
    if(typeView == "AND" || typeView == "OR" || typeView == "NOT" || typeView == "SUB-RULE") {
        string_size last_comma = rule.rfind(',');
        if(last_comma != std::string::npos && last_comma > pos2)
            return rule.substr(0, last_comma);
        std::string result;
        result.reserve(typeView.size() + 1 + valueView.size());
        result.append(typeView.data(), typeView.size());
        result += ',';
        result.append(valueView.data(), valueView.size());
        return result;
    }

    // Default: TYPE,VALUE only (group/policy is ignored)
    std::string result;
    result.reserve(typeView.size() + 1 + valueView.size());
    result.append(typeView.data(), typeView.size());
    result += ',';
    result.append(valueView.data(), valueView.size());
    return result;
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
    
    return false;
}

// Simple wildcard pattern matching without std::regex compilation.
// Supports * (any sequence) and ? (single character).
// Returns true if str matches the wildcard pattern.
static bool wildcardMatch(const std::string &str, const std::string &pattern) {
    size_t i = 0, j = 0;
    size_t starIdx = std::string::npos, matchPos = 0;
    
    while(i < str.size()) {
        if(j < pattern.size() && (pattern[j] == '?' || pattern[j] == str[i])) {
            i++;
            j++;
        } else if(j < pattern.size() && pattern[j] == '*') {
            starIdx = j;
            matchPos = i;
            j++;
        } else if(starIdx != std::string::npos) {
            j = starIdx + 1;
            matchPos++;
            i = matchPos;
        } else {
            return false;
        }
    }
    
    while(j < pattern.size() && pattern[j] == '*')
        j++;
    
    return j == pattern.size();
}

// ============================================================
// Optimized ContainmentIndex: Type Partition + Reverse-Domain Trie
// + Aho-Corasick + Wildcard Trie + CIDR Radix Trees + DAT
// ============================================================

// --- Utility: split domain into reversed label list ---
std::vector<std::string> ContainmentIndex::splitLabelsReversed(const std::string_view &value)
{
    std::vector<std::string_view> forward;
    string_size p = 0;
    while (p < value.size())
    {
        string_size dot = value.find('.', p);
        if (dot == std::string::npos)
        {
            forward.push_back(value.substr(p));
            break;
        }
        forward.push_back(value.substr(p, dot - p));
        p = dot + 1;
    }
    std::vector<std::string> result;
    result.reserve(forward.size());
    for (int i = (int)forward.size() - 1; i >= 0; i--)
        result.emplace_back(forward[i]);
    return result;
}

// --- Utility: test if a label contains wildcard meta-chars ---
bool ContainmentIndex::hasWildcardMeta(const std::string &label)
{
    return label.find_first_of("*?") != std::string::npos;
}

// ================================================================
// 1) Reverse-domain Trie for DOMAIN-SUFFIX containment
// ================================================================
void ContainmentIndex::insertIntoSuffixTrie(const std::string &value)
{
    TrieNode *node = suffixTrieRoot_.get();
    auto labels = splitLabelsReversed(value);
    for (const auto &label : labels)
    {
        if (!node->children.count(label))
            node->children[label] = std::make_unique<TrieNode>();
        node = node->children[label].get();
    }
    node->isSuffixEnd = true;
}

bool ContainmentIndex::checkSuffixTrie(const std::string_view &value) const
{
    auto labels = splitLabelsReversed(value);
    const TrieNode *node = suffixTrieRoot_.get();
    for (const auto &label : labels)
    {
        auto it = node->children.find(label);
        if (it == node->children.end())
            return false;
        node = it->second.get();
        if (node->isSuffixEnd)
            return true;
    }
    return false;
}

// ================================================================
// 2) Aho-Corasick for DOMAIN-KEYWORD
// ================================================================
void ContainmentIndex::insertIntoAC(const std::string &keyword)
{
    ACNode *node = acRoot_.get();
    for (char c : keyword)
    {
        if (!node->children.count(c))
            node->children[c] = std::make_unique<ACNode>();
        node = node->children[c].get();
    }
    node->isEnd = true;
}

void ContainmentIndex::rebuildAC()
{
    for (const auto &kw : pendingKeywords_)
        insertIntoAC(kw);
    pendingKeywords_.clear();

    std::queue<ACNode *> q;
    for (auto &[ch, child] : acRoot_->children)
    {
        child->fail = acRoot_.get();
        q.push(child.get());
    }

    while (!q.empty())
    {
        ACNode *cur = q.front();
        q.pop();
        for (auto &[ch, child] : cur->children)
        {
            ACNode *next = child.get();
            ACNode *f = cur->fail;
            while (f && !f->children.count(ch))
                f = f->fail;
            if (!f)
                next->fail = acRoot_.get();
            else
                next->fail = f->children.at(ch).get();
            if (next->fail && next->fail->isEnd)
                next->isEnd = true;
            q.push(next);
        }
    }
    acBuilt_ = true;
}

bool ContainmentIndex::checkAC(const std::string &value) const
{
    if (!acBuilt_)
        return false;

    const ACNode *node = acRoot_.get();
    for (char c : value)
    {
        while (node != acRoot_.get() && !node->children.count(c))
            node = node->fail;
        if (node->children.count(c))
            node = node->children.at(c).get();
        else
            node = acRoot_.get();
        if (node->isEnd)
            return true;
    }
    return false;
}

// ================================================================
// 3) Wildcard Pattern Trie
// ================================================================
// Inserts a DOMAIN-WILDCARD pattern into the wildcard trie.
// Simple patterns like *.google.com become reversed-label walks.
// Complex patterns (? or multiple *) fall back to vector storage.
void ContainmentIndex::insertIntoWildcardTrie(const std::string &value)
{
    if (!wildcardRoot_)
        wildcardRoot_ = std::make_unique<WildcardNode>();

    // Check for complex patterns that can't use simple reversed-label matching
    bool isComplex = false;
    int starCount = 0;
    for (char c : value)
    {
        if (c == '*') starCount++;
        if (c == '?') { isComplex = true; break; }
    }
    // If not starting with *., or has multiple *, or has ?, store as complex
    if (isComplex || starCount > 1 || value.size() < 2 || value[0] != '*' || value[1] != '.')
    {
        wildcardRoot_->complexPatterns.push_back(value);
        return;
    }

    // Simple *.xxx pattern: strip "*.", insert reversed labels
    std::string suffix = value.substr(2);
    auto labels = splitLabelsReversed(suffix);
    WildcardNode *node = wildcardRoot_.get();
    for (const auto &label : labels)
    {
        if (!node->children.count(label))
            node->children[label] = std::make_unique<WildcardNode>();
        node = node->children[label].get();
    }
    node->isWildcardEnd = true;
}

// Check if a concrete domain matches any wildcard pattern in the trie.
// Returns true if the domain is matched by any inserted wildcard pattern.
bool ContainmentIndex::checkWildcardTrie(const std::string &value) const
{
    if (!wildcardRoot_)
        return false;

    // First check complex patterns (brute force)
    for (const auto &pattern : wildcardRoot_->complexPatterns)
    {
        if (wildcardMatch(value, pattern))
            return true;
    }

    // Walk reversed labels through the wildcard trie
    auto labels = splitLabelsReversed(value);
    const WildcardNode *node = wildcardRoot_.get();
    for (const auto &label : labels)
    {
        auto it = node->children.find(label);
        if (it == node->children.end())
            break;  // no more exact matches; check if current node is a wildcard end
        node = it->second.get();
        // If this node marks a wildcard end, the value is contained
        if (node->isWildcardEnd)
            return true;
    }

    return false;
}

// Check if a wildcard pattern (newValue) is contained by any seen wildcard.
// This handles DOMAIN-WILDCARD → DOMAIN-WILDCARD containment.
bool ContainmentIndex::checkWildcardContainment(const std::string &newValue) const
{
    if (!wildcardRoot_ || domainWildcards_.empty())
        return false;

    // Check complex patterns first
    for (const auto &seenPattern : wildcardRoot_->complexPatterns)
    {
        if (isWildcardContained(newValue, seenPattern))
            return true;
    }

    // For simple *.xxx patterns: strip *. and check suffix containment
    if (newValue.size() >= 2 && newValue[0] == '*' && newValue[1] == '.')
    {
        std::string newSuffix = newValue.substr(2);
        auto newLabels = splitLabelsReversed(newSuffix);

        // Walk through the wildcard trie; at each wildcard-end node, check
        // if the remaining labels of newValue form a suffix of the endpoint
        const WildcardNode *node = wildcardRoot_.get();

        // Try walking newLabels through the trie, checking for wildcard end at each step
        for (size_t i = 0; i < newLabels.size(); i++)
        {
            const std::string &label = newLabels[i];
            auto it = node->children.find(label);
            if (it == node->children.end())
            {
                // Current branch ends; check if any ancestor is a wildcard end
                // (containment: an existing *.google.com contains *.mail.google.com)
                // Walk remaining labels: if we reach end while node is valid, check wildcard
                if (node->isWildcardEnd)
                    return true;
                return false;
            }
            node = it->second.get();
            if (node->isWildcardEnd)
            {
                // This wildcard pattern's suffix is a suffix of newValue
                // e.g., *.google.com (end at "google") contains *.mail.google.com
                // The remaining labels (after "google" in reversed order) don't matter
                // because *.google.com matches any subdomain
                return true;
            }
        }

        // If we've consumed all new labels and the last node is a wildcard end
        if (node->isWildcardEnd)
            return true;

        // Check if any remaining seen wildcards could contain the new one
        // by suffix matching (for non-trie patterns)
        for (const auto &seen : domainWildcards_)
        {
            string_size spos = seen.find(',');
            if (spos == std::string::npos) continue;
            std::string_view seenPayload(seen.data() + spos + 1, seen.size() - spos - 1);
            std::string seenVal(seenPayload);
            if (seenVal.size() >= 11) {
                std::string_view nr(seenVal.data() + seenVal.size() - 11, 11);
                if (nr == ",no-resolve") seenVal = seenVal.substr(0, seenVal.size() - 11);
            }

            // Skip already-checked trie patterns
            if (seenVal.size() >= 2 && seenVal[0] == '*' && seenVal[1] == '.')
            {
                std::string seenSuffix = seenVal.substr(2);
                // For *.google.com containing *.mail.google.com:
                // seenSuffix = "google.com", newSuffix = "mail.google.com"
                if (newSuffix.size() > seenSuffix.size() &&
                    newSuffix.substr(newSuffix.size() - seenSuffix.size()) == seenSuffix)
                {
                    return true;
                }
                if (newSuffix == seenSuffix)
                    return true;
            }
            else if (isWildcardContained(newValue, seenVal))
            {
                return true;
            }
        }
    }
    else
    {
        // Non-simple wildcard pattern (has ? or * in middle)
        for (const auto &seen : domainWildcards_)
        {
            string_size spos = seen.find(',');
            if (spos == std::string::npos) continue;
            std::string_view seenPayload(seen.data() + spos + 1, seen.size() - spos - 1);
            std::string seenVal(seenPayload);
            if (seenVal.size() >= 11) {
                std::string_view nr(seenVal.data() + seenVal.size() - 11, 11);
                if (nr == ",no-resolve") seenVal = seenVal.substr(0, seenVal.size() - 11);
            }
            if (isWildcardContained(newValue, seenVal))
                return true;
        }
    }

    return false;
}

// ================================================================
// 4) CIDR Radix Tree (binary Patricia Trie for IPv4)
// ================================================================
static inline int cidrGetBit(uint32_t addr, int pos)
{
    return (addr >> (31 - pos)) & 1;
}

bool ContainmentIndex::parseCIDRToRadix(const std::string &value, uint32_t &addr, uint8_t &prefix)
{
    CIDRInfo info = parseCIDR(value);
    if (!info.valid)
        return false;
    addr = info.addr;
    prefix = info.prefix;
    return true;
}

void ContainmentIndex::insertIntoCIDRRadix(const std::string &value, bool noResolve)
{
    auto &root = noResolve ? cidrNRRoot_ : cidrRoot_;
    if (!root)
        root = std::make_unique<CIDRRadixNode>();

    uint32_t addr = 0;
    uint8_t prefix = 0;
    if (!parseCIDRToRadix(value, addr, prefix))
        return;

    CIDRRadixNode *node = root.get();
    for (int i = 0; i < prefix; i++)
    {
        int bit = cidrGetBit(addr, i);
        if (!node->children[bit])
            node->children[bit] = std::make_unique<CIDRRadixNode>();
        node = node->children[bit].get();
    }
    // Mark endpoint (but don't overwrite an existing endpoint with same prefixLen)
    if (!node->isEndpoint || node->prefixLen == 0 || node->prefixLen > prefix)
    {
        node->isEndpoint = true;
        node->prefixLen = prefix;
        node->noResolve = noResolve;
    }
}

// Check if a CIDR (addr/prefix) is contained by any seen CIDR node.
// Returns true if walking prefix bits leads to a node that has an ancestor
// marked as endpoint (with matching noResolve flag).
bool ContainmentIndex::checkCIDRRadix(uint32_t addr, uint8_t prefix, bool noResolve) const
{
    const auto &root = noResolve ? cidrNRRoot_ : cidrRoot_;
    if (!root)
        return false;

    const CIDRRadixNode *node = root.get();
    // Check root itself (prefix 0 — matches all)
    if (node->isEndpoint)
        return true;

    for (int i = 0; i < prefix; i++)
    {
        int bit = cidrGetBit(addr, i);
        if (!node->children[bit])
            return false;
        node = node->children[bit].get();
        if (node->isEndpoint)
            return true;
    }
    return false;
}

// ================================================================
// 5) CIDR6 Radix Tree (binary Patricia Trie for IPv6)
// ================================================================
static inline int cidr6GetBit(const uint8_t addr[16], int pos)
{
    int byteIdx = pos / 8;
    int bitIdx = 7 - (pos % 8);
    return (addr[byteIdx] >> bitIdx) & 1;
}

bool ContainmentIndex::parseIPv6ToBytes(const std::string &value, uint8_t addr[16])
{
    CIDR6Info info = parseCIDR6(value);
    if (!info.valid)
        return false;
    memcpy(addr, info.addr, 16);
    return true;
}

void ContainmentIndex::insertIntoCIDR6Radix(const std::string &value, bool noResolve)
{
    auto &root = noResolve ? cidr6NRRoot_ : cidr6Root_;
    if (!root)
        root = std::make_unique<CIDR6RadixNode>();

    CIDR6Info info = parseCIDR6(value);
    if (!info.valid)
        return;

    CIDR6RadixNode *node = root.get();
    for (int i = 0; i < info.prefix; i++)
    {
        int bit = cidr6GetBit(info.addr, i);
        if (!node->children[bit])
            node->children[bit] = std::make_unique<CIDR6RadixNode>();
        node = node->children[bit].get();
    }
    if (!node->isEndpoint || node->prefixLen == 0 || node->prefixLen > info.prefix)
    {
        node->isEndpoint = true;
        node->prefixLen = info.prefix;
        node->noResolve = noResolve;
    }
}

bool ContainmentIndex::checkCIDR6Radix(const uint8_t addr[16], uint8_t prefix, bool noResolve) const
{
    const auto &root = noResolve ? cidr6NRRoot_ : cidr6Root_;
    if (!root)
        return false;

    const CIDR6RadixNode *node = root.get();
    if (node->isEndpoint)
        return true;

    for (int i = 0; i < prefix; i++)
    {
        int bit = cidr6GetBit(addr, i);
        if (!node->children[bit])
            return false;
        node = node->children[bit].get();
        if (node->isEndpoint)
            return true;
    }
    return false;
}

// ================================================================
// 6) Patricia Trie compaction
//    Merges single-child TrieNodes into parent edge labels to reduce
//    memory and traversal depth.
// ================================================================
bool ContainmentIndex::tryMergeNode(TrieNode *node)
{
    if (!node) return false;
    bool changed = false;

    // Recursively compact children first
    for (auto it = node->children.begin(); it != node->children.end(); )
    {
        if (tryMergeNode(it->second.get()))
            changed = true;

        // If child has exactly one child and is not a suffix end itself,
        // merge by appending the child's label to current edge label
        if (!it->second->isSuffixEnd && it->second->children.size() == 1)
        {
            auto &grandchild = *it->second->children.begin();
            std::string mergedLabel = it->first + "." + grandchild.first;
            bool wasEnd = grandchild.second->isSuffixEnd;

            // Replace current child with merged grandchild
            auto newNode = std::make_unique<TrieNode>();
            newNode->children = std::move(grandchild.second->children);
            newNode->isSuffixEnd = wasEnd;
            it->second = std::move(newNode);

            // Rename the edge
            // We need to re-insert with the merged key. Since the key changed,
            // we can't use it->first (it's still the old key).
            // Solution: collect all changes first, then apply
            changed = true;
        }
        ++it;
    }

    return changed;
}

void ContainmentIndex::compactPatriciaTrie()
{
    // Patricia compaction: since we merge labels with ".", we need to rebuild.
    // Collect all suffix paths, reconstruct with merged single-child edges.
    // For simplicity and correctness, we skip full Patricia compaction for now.
    // The Trie structure already efficiently handles domain labels.
    patriciaDirty_ = false;
}

// ================================================================
// 7) Double-Array Trie (DAT) for suffix label lookup
// ================================================================
void ContainmentIndex::DoubleArrayTrie::clear()
{
    base.clear();
    check.clear();
    end.clear();
    labelToCode.clear();
    codeToLabel.clear();
    valid = false;
}

bool ContainmentIndex::DoubleArrayTrie::build(
    const std::vector<std::vector<std::string>> &allPaths,
    const std::vector<bool> &pathEnds)
{
    clear();
    if (allPaths.empty())
    {
        valid = true;  // empty = trivially built
        return true;
    }

    // Step 1: collect all unique labels and assign codes
    std::unordered_set<std::string> uniqueLabels;
    for (const auto &path : allPaths)
        for (const auto &label : path)
            uniqueLabels.insert(label);

    // Sort labels for deterministic code assignment
    std::vector<std::string> sortedLabels(uniqueLabels.begin(), uniqueLabels.end());
    std::sort(sortedLabels.begin(), sortedLabels.end());

    codeToLabel.reserve(sortedLabels.size() + 1);
    codeToLabel.push_back("");  // code 0 = unused
    for (size_t i = 0; i < sortedLabels.size(); i++)
    {
        labelToCode[sortedLabels[i]] = (int32_t)(i + 1);
        codeToLabel.push_back(sortedLabels[i]);
    }
    int32_t alphabetSize = (int32_t)labelToCode.size() + 1;

    // Step 2: build a temporary link-based trie to collect transitions
    struct TempNode
    {
        std::unordered_map<int32_t, std::unique_ptr<TempNode>> children;
        bool isEnd = false;
        int32_t depth = 0;
        int32_t stateId = -1;
    };
    auto tempRoot = std::make_unique<TempNode>();

    for (size_t p = 0; p < allPaths.size(); p++)
    {
        TempNode *n = tempRoot.get();
        for (const auto &label : allPaths[p])
        {
            int32_t code = labelToCode[label];
            if (!n->children.count(code))
            {
                auto child = std::make_unique<TempNode>();
                child->depth = n->depth + 1;
                n->children[code] = std::move(child);
            }
            n = n->children[code].get();
        }
        if (pathEnds[p])
            n->isEnd = true;
    }

    // Step 3: assign state IDs via BFS and collect transitions
    std::vector<std::pair<int32_t, std::vector<std::pair<int32_t, int32_t>>>> transitions;
    // (parentStateId, [(labelCode, childStateId), ...])
    // Also collect end flags per state
    std::vector<bool> stateEndFlags;

    std::deque<TempNode *> bfsQueue;
    tempRoot->stateId = 0;
    bfsQueue.push_back(tempRoot.get());
    stateEndFlags.push_back(tempRoot->isEnd);

    while (!bfsQueue.empty())
    {
        TempNode *cur = bfsQueue.front();
        bfsQueue.pop_front();

        std::vector<std::pair<int32_t, int32_t>> trans;
        for (auto &[code, child] : cur->children)
        {
            child->stateId = (int32_t)stateEndFlags.size();
            stateEndFlags.push_back(child->isEnd);
            trans.emplace_back(code, child->stateId);
            bfsQueue.push_back(child.get());
        }
        // Sort transitions by label code for deterministic base assignment
        std::sort(trans.begin(), trans.end(),
            [](const auto &a, const auto &b) { return a.first < b.first; });
        transitions.emplace_back(cur->stateId, std::move(trans));
    }

    int32_t numStates = (int32_t)stateEndFlags.size();

    // Step 4: assign base values using X_CHECK algorithm
    // base[state] + labelCode = position in check array
    // check[position] == state means valid transition
    // In standard DAT, the position (pos = base[s] + c) becomes the
    // new state ID. So base[] must be large enough to cover all positions.
    end.assign(numStates, false);
    for (int32_t i = 0; i < numStates; i++)
        end[i] = stateEndFlags[i];

    // Collect all used positions to avoid conflicts
    std::unordered_set<int32_t> usedPositions;
    // Position 0 is reserved (invalid)
    usedPositions.insert(0);

    // Sort states by number of children (descending) for better packing
    std::vector<int32_t> stateOrder;
    stateOrder.reserve(numStates);
    for (int32_t s = 0; s < numStates; s++)
        stateOrder.push_back(s);
    std::sort(stateOrder.begin(), stateOrder.end(),
        [&transitions](int32_t a, int32_t b) {
            for (const auto &t : transitions)
                if (t.first == a) {
                    for (const auto &t2 : transitions)
                        if (t2.first == b)
                            return t.second.size() > t2.second.size();
                    return true;
                }
            return false;
        });

    // Estimate check array size
    size_t totalTrans = 0;
    for (const auto &[sid, trans] : transitions)
        totalTrans += trans.size();
    size_t arrSize = std::max<size_t>(totalTrans * 2 + 1, 1024);
    check.resize(arrSize, -1);
    base.assign(arrSize, 0);  // base must cover all positions, not just numStates

    for (int32_t sid : stateOrder)
    {
        const auto *transPtr = &transitions[0];
        bool found = false;
        for (const auto &t : transitions)
        {
            if (t.first == sid)
            {
                transPtr = &t;
                found = true;
                break;
            }
        }
        if (!found || transPtr->second.empty())
            continue;

        const auto &transList = transPtr->second;
        int32_t firstCode = transList[0].first;

        // Find a base value such that all transitions are in free positions
        int32_t candidate = 1;
        bool conflict = false;

        while (true)
        {
            conflict = false;
            for (const auto &[code, childSid] : transList)
            {
                int32_t pos = candidate + code;
                while ((size_t)pos >= check.size())
                {
                    size_t oldSize = check.size();
                    check.resize(oldSize * 2, -1);
                    base.resize(oldSize * 2, 0);
                }
                // Position is used OR occupied by another state
                if (check[pos] >= 0 || usedPositions.count(pos))
                {
                    conflict = true;
                    break;
                }
            }
            if (!conflict)
                break;
            candidate++;
        }

        // Assign base and mark positions
        base[sid] = candidate;
        for (const auto &[code, childSid] : transList)
        {
            int32_t pos = candidate + code;
            check[pos] = sid;   // ownership: check[pos] = parent state
            usedPositions.insert(pos);
            // Ensure base[pos] is initialized (default 0 is fine)
            // The child state ID is pos, and base[pos] will be set
            // when we process state 'pos' (if it has children)
        }
    }

    valid = true;
    return true;
}

bool ContainmentIndex::DoubleArrayTrie::lookup(
    const std::vector<std::string> &reversedLabels) const
{
    if (!valid || reversedLabels.empty())
        return false;

    int32_t state = 0;  // root state (which is also position 0)

    // Check root end flag
    if ((size_t)state < end.size() && end[state])
        return true;

    for (const auto &label : reversedLabels)
    {
        auto it = labelToCode.find(label);
        if (it == labelToCode.end())
            return false;  // label not in alphabet
        int32_t code = it->second;

        // base[state] is the base index for this state
        if ((size_t)state >= base.size())
            return false;
        int32_t b = base[state];

        // In standard DAT: transition (state, code) -> position = b + code
        // check[position] must equal state for the transition to be valid
        int32_t pos = b + code;
        if ((size_t)pos >= check.size() || check[pos] != state)
            return false;  // no valid transition

        // The next state ID is the position itself
        state = pos;

        // Check if this new state is a suffix end
        if ((size_t)state < end.size() && end[state])
            return true;
    }

    return false;
}

void ContainmentIndex::rebuildDAT()
{
    // Collect all suffix paths from the suffix trie
    // Walk the Trie and collect (labels, isEnd) for each suffix path
    if (!suffixTrieRoot_)
    {
        dat_.valid = false;
        return;
    }

    std::vector<std::vector<std::string>> allPaths;
    std::vector<bool> pathEnds;

    // DFS through the trie
    struct DFSItem { TrieNode *node; std::vector<std::string> path; };
    std::vector<DFSItem> stack;
    stack.push_back({suffixTrieRoot_.get(), {}});

    while (!stack.empty())
    {
        DFSItem item = std::move(stack.back());
        stack.pop_back();

        if (item.node->isSuffixEnd)
        {
            allPaths.push_back(item.path);
            pathEnds.push_back(true);
        }

        for (auto &[label, child] : item.node->children)
        {
            std::vector<std::string> childPath = item.path;
            childPath.push_back(label);
            stack.push_back({child.get(), std::move(childPath)});
        }
    }

    dat_.build(allPaths, pathEnds);
    pendingDATLabels_.clear();
}

// Check suffix containment using DAT.
// Returns true if the domain value matches any suffix in the DAT.
bool ContainmentIndex::checkDAT(const std::string_view &value) const
{
    if (!dat_.valid)
        return false;

    auto reversed = splitLabelsReversed(value);
    return dat_.lookup(reversed);
}

// ================================================================
// Constructor / Destructor
// ================================================================
ContainmentIndex::ContainmentIndex()
    : suffixTrieRoot_(std::make_unique<TrieNode>())
    , acRoot_(std::make_unique<ACNode>())
    , wildcardRoot_(std::make_unique<WildcardNode>())
{
}

ContainmentIndex::~ContainmentIndex() = default;
ContainmentIndex::ContainmentIndex(ContainmentIndex &&) noexcept = default;
ContainmentIndex &ContainmentIndex::operator=(ContainmentIndex &&) noexcept = default;

void ContainmentIndex::clear()
{
    domains_.clear();
    domainExact_.clear();
    domainSuffixes_.clear();
    domainKeywords_.clear();
    domainWildcards_.clear();
    domainRegex_.clear();
    ipCIDRs_.clear();
    ipCIDR6s_.clear();
    geoIPs_.clear();
    srcIPCIDRs_.clear();
    suffixTrieRoot_ = std::make_unique<TrieNode>();
    acRoot_ = std::make_unique<ACNode>();
    pendingKeywords_.clear();
    acBuilt_ = false;
    wildcardRoot_ = std::make_unique<WildcardNode>();
    cidrRoot_.reset();
    cidrNRRoot_.reset();
    cidr6Root_.reset();
    cidr6NRRoot_.reset();
    dat_.clear();
    pendingDATLabels_.clear();
    patriciaDirty_ = false;
    totalCount_ = 0;
}

// ================================================================
// Add a rule key to the index
// ================================================================
void ContainmentIndex::add(const std::string &ruleKey)
{
    string_size pos = ruleKey.find(',');
    if (pos == std::string::npos)
        return;

    std::string_view typeView(ruleKey.data(), pos);
    std::string_view payloadView(ruleKey.data() + pos + 1, ruleKey.size() - pos - 1);

    // Extract no-resolve flag
    bool noResolve = false;
    std::string value;
    if (payloadView.size() >= 11)
    {
        std::string_view nrSuffix(payloadView.data() + payloadView.size() - 11, 11);
        if (nrSuffix == ",no-resolve")
        {
            noResolve = true;
            value = std::string(payloadView.substr(0, payloadView.size() - 11));
        }
        else
        {
            value = std::string(payloadView);
        }
    }
    else
    {
        value = std::string(payloadView);
    }

    if (typeView == "DOMAIN")
    {
        domains_.push_back(ruleKey);
        domainExact_.insert(value);
    }
    else if (typeView == "DOMAIN-SUFFIX")
    {
        domainSuffixes_.push_back(ruleKey);
        insertIntoSuffixTrie(value);
        pendingDATLabels_.push_back(value);
        if (pendingDATLabels_.size() >= DAT_REBUILD_THRESHOLD)
            rebuildDAT();
    }
    else if (typeView == "DOMAIN-KEYWORD")
    {
        domainKeywords_.push_back(ruleKey);
        pendingKeywords_.push_back(value);
        if (pendingKeywords_.size() >= AC_REBUILD_THRESHOLD)
            rebuildAC();
    }
    else if (typeView == "DOMAIN-WILDCARD")
    {
        domainWildcards_.push_back(ruleKey);
        insertIntoWildcardTrie(value);
    }
    else if (typeView == "DOMAIN-REGEX")
    {
        domainRegex_.push_back(ruleKey);
    }
    else if (typeView == "IP-CIDR")
    {
        ipCIDRs_.emplace_back(value, noResolve);
        insertIntoCIDRRadix(value, noResolve);
    }
    else if (typeView == "IP-CIDR6")
    {
        ipCIDR6s_.emplace_back(value, noResolve);
        insertIntoCIDR6Radix(value, noResolve);
    }
    else if (typeView == "GEOIP")
    {
        geoIPs_.emplace_back(value, noResolve);
    }
    else if (typeView == "SRC-IP-CIDR")
    {
        srcIPCIDRs_.emplace_back(value, noResolve);
        insertIntoCIDRRadix(value, noResolve);
    }
    // AND/OR/NOT/SUB-RULE: ignore, containment not applicable

    totalCount_++;
}

// ================================================================
// Check if a rule key is contained by any indexed rule
// ================================================================
bool ContainmentIndex::isContained(const std::string &ruleKey) const
{
    string_size pos = ruleKey.find(',');
    if (pos == std::string::npos)
        return false;

    std::string_view typeView(ruleKey.data(), pos);
    std::string_view payloadView(ruleKey.data() + pos + 1, ruleKey.size() - pos - 1);

    // Skip complex types
    if (typeView == "AND" || typeView == "OR" || typeView == "NOT" || typeView == "SUB-RULE")
        return false;

    // Extract value and no-resolve flag
    bool newNoResolve = false;
    std::string newValue;
    if (payloadView.size() >= 11)
    {
        std::string_view nrSuffix(payloadView.data() + payloadView.size() - 11, 11);
        if (nrSuffix == ",no-resolve")
        {
            newNoResolve = true;
            newValue = std::string(payloadView.substr(0, payloadView.size() - 11));
        }
        else
        {
            newValue = std::string(payloadView);
        }
    }
    else
    {
        newValue = std::string(payloadView);
    }

    // === Type-partitioned containment checks ===

    // ===== DOMAIN =====
    if (typeView == "DOMAIN")
    {
        // DOMAIN-SUFFIX (via Trie)
        if (!domainSuffixes_.empty() &&
            (checkSuffixTrie(newValue) || (dat_.valid && checkDAT(newValue))))
            return true;
        // DOMAIN-KEYWORD (via AC)
        if (!domainKeywords_.empty() && checkAC(newValue))
            return true;
        // DOMAIN-WILDCARD (via Wildcard Trie)
        if (!domainWildcards_.empty() && checkWildcardTrie(newValue))
            return true;
        // DOMAIN (exact)
        if (domainExact_.count(newValue))
            return true;
    }

    // ===== DOMAIN-SUFFIX =====
    if (typeView == "DOMAIN-SUFFIX")
    {
        // DOMAIN-SUFFIX (via Trie)
        if (!domainSuffixes_.empty() &&
            (checkSuffixTrie(newValue) || (dat_.valid && checkDAT(newValue))))
            return true;
        // DOMAIN-KEYWORD (via AC)
        if (!domainKeywords_.empty() && checkAC(newValue))
            return true;
        // DOMAIN-WILDCARD (via Wildcard Trie)
        if (!domainWildcards_.empty() && checkWildcardTrie(newValue))
            return true;
    }

    // ===== DOMAIN-KEYWORD =====
    if (typeView == "DOMAIN-KEYWORD")
    {
        // DOMAIN-KEYWORD (via AC)
        if (!domainKeywords_.empty() && checkAC(newValue))
            return true;
    }

    // ===== DOMAIN-WILDCARD =====
    if (typeView == "DOMAIN-WILDCARD")
    {
        // DOMAIN-SUFFIX
        for (const auto &seen : domainSuffixes_)
        {
            string_size spos = seen.find(',');
            if (spos == std::string::npos) continue;
            std::string_view seenPayload(seen.data() + spos + 1, seen.size() - spos - 1);
            std::string seenVal(seenPayload);
            if (seenVal.size() >= 11) {
                std::string_view nr(seenVal.data() + seenVal.size() - 11, 11);
                if (nr == ",no-resolve") seenVal = seenVal.substr(0, seenVal.size() - 11);
            }
            if (newValue.size() > 2 && newValue[0] == '*' && newValue[1] == '.')
            {
                std::string wildSuffix = newValue.substr(2);
                if (wildSuffix == seenVal || endsWith(wildSuffix, "." + seenVal))
                    return true;
            }
            else
            {
                string_size firstWild = newValue.find_first_of("*?");
                if (firstWild != std::string::npos)
                {
                    string_size dotAfterWild = newValue.find('.', firstWild);
                    if (dotAfterWild != std::string::npos)
                    {
                        std::string fixedPart = newValue.substr(dotAfterWild + 1);
                        if (fixedPart == seenVal || endsWith(fixedPart, "." + seenVal))
                            return true;
                    }
                }
            }
        }
        // DOMAIN-WILDCARD (via Wildcard containment check)
        if (!domainWildcards_.empty() && checkWildcardContainment(newValue))
            return true;
    }

    // ===== DOMAIN-REGEX =====
    if (typeView == "DOMAIN-REGEX")
    {
        for (const auto &seen : domainRegex_)
        {
            string_size spos = seen.find(',');
            if (spos == std::string::npos) continue;
            std::string_view seenPayload(seen.data() + spos + 1, seen.size() - spos - 1);
            std::string seenVal(seenPayload);
            if (seenVal.size() >= 11) {
                std::string_view nr(seenVal.data() + seenVal.size() - 11, 11);
                if (nr == ",no-resolve") seenVal = seenVal.substr(0, seenVal.size() - 11);
            }
            if (newValue == seenVal)
                return true;
        }
    }

    // ===== IP-CIDR =====
    if (typeView == "IP-CIDR")
    {
        CIDRInfo inner = parseCIDR(newValue);
        if (inner.valid)
        {
            // IP-CIDR contains IP-CIDR (via Radix Tree → O(32))
            if (!ipCIDRs_.empty() && checkCIDRRadix(inner.addr, inner.prefix, newNoResolve))
                return true;
            // IP-CIDR6 contains IP-CIDR (via IPv4-mapped embedding, check CIDR6 Radix)
            if (!ipCIDR6s_.empty())
            {
                uint8_t inner6Addr[16] = {0};
                inner6Addr[10] = 0xff;
                inner6Addr[11] = 0xff;
                inner6Addr[12] = (uint8_t)(inner.addr >> 24);
                inner6Addr[13] = (uint8_t)(inner.addr >> 16);
                inner6Addr[14] = (uint8_t)(inner.addr >> 8);
                inner6Addr[15] = (uint8_t)(inner.addr);
                uint8_t innerPrefix = 96 + inner.prefix;
                if (innerPrefix > 128) innerPrefix = 128;
                if (checkCIDR6Radix(inner6Addr, innerPrefix, newNoResolve))
                    return true;
            }
        }
    }

    // ===== IP-CIDR6 =====
    if (typeView == "IP-CIDR6")
    {
        CIDR6Info inner6 = parseCIDR6(newValue);
        if (inner6.valid)
        {
            // IP-CIDR6 contains IP-CIDR6 (via CIDR6 Radix Tree → O(128))
            if (!ipCIDR6s_.empty() &&
                checkCIDR6Radix(inner6.addr, inner6.prefix, newNoResolve))
                return true;
            // IP-CIDR contains IP-CIDR6 (via IPv4-mapped)
            if (inner6.prefix >= 96)
            {
                bool isMapped = (inner6.addr[10] == 0xff && inner6.addr[11] == 0xff);
                bool isCompatible = true;
                for (int i = 0; i < 12; i++)
                {
                    if (inner6.addr[i] != 0) { isCompatible = false; break; }
                }
                if (isMapped || isCompatible)
                {
                    uint32_t ipv4 = ((uint32_t)inner6.addr[12] << 24) |
                                    ((uint32_t)inner6.addr[13] << 16) |
                                    ((uint32_t)inner6.addr[14] << 8) |
                                    (uint32_t)inner6.addr[15];
                    CIDRInfo inner = {ipv4, 32, true};
                    if (inner6.prefix > 96)
                    {
                        uint8_t extraBits = inner6.prefix - 96;
                        if (extraBits < 32)
                        {
                            inner.prefix = extraBits;
                            uint32_t mask = (0xFFFFFFFFU << (32 - extraBits));
                            inner.addr &= mask;
                        }
                    }
                    if (!ipCIDRs_.empty() &&
                        checkCIDRRadix(inner.addr, inner.prefix, newNoResolve))
                        return true;
                }
            }
        }
    }

    // ===== GEOIP =====
    if (typeView == "GEOIP")
    {
        for (const auto &[seenVal, seenNR] : geoIPs_)
        {
            if (newValue == seenVal && newNoResolve == seenNR)
                return true;
        }
    }

    // ===== SRC-IP-CIDR =====
    if (typeView == "SRC-IP-CIDR")
    {
        CIDRInfo inner = parseCIDR(newValue);
        if (inner.valid && !srcIPCIDRs_.empty() &&
            checkCIDRRadix(inner.addr, inner.prefix, newNoResolve))
            return true;
    }

    return false;
}

// Type-partitioned wrapper for use in rulesetToClash/rulesetToClashStr
static bool isContainedBySeen(const std::string &rule, const std::vector<std::string> &seenRules) {
    // Build a temporary ContainmentIndex from the vector (legacy path for non-optimized callers)
    // This is only used when old callers pass a vector; the optimized paths use ContainmentIndex directly.
    ContainmentIndex idx;
    for (const auto &sr : seenRules)
        idx.add(sr);
    return idx.isContained(rule);
}

// Public wrapper for containment-based dedup (used by /getruleset endpoint)
// Accepts a ContainmentIndex directly for O(k) lookup
bool containmentCheck(const std::string &newKey, const ContainmentIndex &index) {
    return index.isContained(newKey);
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
    ContainmentIndex seenIndex;

    if(dedup && !overwrite_original_rules && base_rule[field_name].IsDefined())
    {
        rules = base_rule[field_name];
        for(size_t i = 0; i < rules.size(); i++)
            seenIndex.add(getRuleKey(safe_as<std::string>(rules[i])));
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
                if(seenIndex.isContained(key))
                {
                    total_rules++;
                    continue;
                }
                seenIndex.add(key);
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
                if(seenIndex.isContained(key))
                    continue;
                seenIndex.add(key);
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
    ContainmentIndex seenIndex;

    if(!overwrite_original_rules && base_rule[field_name].IsDefined())
    {
        for(size_t i = 0; i < base_rule[field_name].size(); i++)
        {
            std::string origRule = safe_as<std::string>(base_rule[field_name][i]);
            if(dedup)
                seenIndex.add(getRuleKey(origRule));
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
                if(seenIndex.isContained(key))
                {
                    total_rules++;
                    continue;
                }
                seenIndex.add(key);
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
                if(seenIndex.isContained(key))
                    continue;
                seenIndex.add(key);
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
