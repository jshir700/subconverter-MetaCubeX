#ifndef RULECONVERT_H_INCLUDED
#define RULECONVERT_H_INCLUDED

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <future>
#include <cstdint>
#include <climits>

#include <yaml-cpp/yaml.h>
#include <rapidjson/document.h>

#include "utils/ini_reader/ini_reader.h"

enum ruleset_type
{
    RULESET_SURGE,
    RULESET_QUANX,
    RULESET_CLASH_DOMAIN,
    RULESET_CLASH_IPCIDR,
    RULESET_CLASH_CLASSICAL
};

struct RulesetContent
{
    std::string rule_group;
    std::string rule_path;
    std::string rule_path_typed;
    int rule_type = RULESET_SURGE;
    std::shared_future<std::string> rule_content;
    int update_interval = 0;
    std::string user_agent;
    std::string proxy;
    bool provider = false;
    bool provider_explicit = false;
    bool provider_override = false;
};

// =====================================================================
// Optimized ContainmentIndex with 5 additional data structures:
// 1) Wildcard Pattern Trie     - O(k) DOMAIN-WILDCARD containment
// 2) CIDR Radix Tree (IPv4)    - O(32) IP-CIDR containment
// 3) CIDR6 Radix Tree (IPv6)   - O(128) IP-CIDR6 containment
// 4) Patricia Trie compression - memory-efficient domain suffix trie
// 5) Double-Array Trie (DAT)   - cache-friendly suffix label lookup
// =====================================================================
class ContainmentIndex
{
public:
    ContainmentIndex();
    ~ContainmentIndex();
    ContainmentIndex(ContainmentIndex &&) noexcept;
    ContainmentIndex &operator=(ContainmentIndex &&) noexcept;

    // Non-copyable
    ContainmentIndex(const ContainmentIndex &) = delete;
    ContainmentIndex &operator=(const ContainmentIndex &) = delete;

    // Add a rule key (TYPE,VALUE or TYPE,VALUE,no-resolve) to the index
    void add(const std::string &ruleKey);

    // Check if a rule key is contained by any already-indexed rule
    bool isContained(const std::string &ruleKey) const;

    // Clear all indexed data
    void clear();

    // Number of rules indexed
    size_t size() const { return totalCount_; }

private:
    // ================================================================
    // 1) Reverse-domain Trie Node (existing, for DOMAIN-SUFFIX)
    // ================================================================
    struct TrieNode
    {
        std::unordered_map<std::string, std::unique_ptr<TrieNode>> children;
        bool isSuffixEnd = false;
    };

    // ================================================================
    // 2) Aho-Corasick Node (existing, for DOMAIN-KEYWORD)
    // ================================================================
    struct ACNode
    {
        std::unordered_map<char, std::unique_ptr<ACNode>> children;
        ACNode *fail = nullptr;
        bool isEnd = false;
    };

    // ================================================================
    // 3) Wildcard Pattern Trie Node (NEW)
    //    - For DOMAIN-WILDCARD patterns like *.google.com
    //    - Insert reversed labels, mark wildcard endpoints
    //    - Complex patterns (? or multiple *) stored as fallback
    // ================================================================
    struct WildcardNode
    {
        std::unordered_map<std::string, std::unique_ptr<WildcardNode>> children;
        bool isWildcardEnd = false;  // pattern like *.google.com (or more specific) ends here
        // Complex patterns with ? or multiple * that can't be perfectly represented
        std::vector<std::string> complexPatterns;
    };

    // ================================================================
    // 4) CIDR Radix Tree Node (NEW) - binary Patricia Trie for IPv4
    //    - Each node branches on one bit of the network address
    //    - children[0] = bit 0, children[1] = bit 1
    //    - isEndpoint + prefixLen mark CIDR ranges
    // ================================================================
    struct CIDRRadixNode
    {
        std::unique_ptr<CIDRRadixNode> children[2];
        uint8_t prefixLen = 0;  // non-zero = this node is a CIDR endpoint
        bool isEndpoint = false;
        bool noResolve = false;
    };

    // ================================================================
    // 5) CIDR6 Radix Tree Node (NEW) - binary Patricia Trie for IPv6
    //    - Same structure as CIDRRadixNode but for 128-bit addresses
    // ================================================================
    struct CIDR6RadixNode
    {
        std::unique_ptr<CIDR6RadixNode> children[2];
        uint8_t prefixLen = 0;
        bool isEndpoint = false;
        bool noResolve = false;
    };

    // ================================================================
    // 6) Double-Array Trie (NEW)
    //    - Cache-friendly replacement for unordered_map label lookup
    //    - base[state] = base index, check[pos] = parent state check
    //    - end[state] = whether state is a suffix end
    //    - Transition: (state, labelCode) -> pos = base[state] + labelCode
    //                   valid if check[pos] == state
    // ================================================================
    struct DoubleArrayTrie
    {
        std::vector<int32_t> base;
        std::vector<int32_t> check;
        std::vector<bool> end;
        std::unordered_map<std::string, int32_t> labelToCode;
        std::vector<std::string> codeToLabel;

        bool valid = false;  // whether the DAT has been successfully built

        void clear();
        bool build(const std::vector<std::vector<std::string>> &allPaths,
                   const std::vector<bool> &pathEnds);
        // Lookup: walk reversed labels, return true if any prefix is a suffix end
        bool lookup(const std::vector<std::string> &reversedLabels) const;
    };

    // ================================================================
    // Type-partitioned storage
    // ================================================================
    std::vector<std::string> domains_;
    std::unordered_set<std::string> domainExact_;  // fast exact lookup for DOMAIN
    std::vector<std::string> domainSuffixes_;
    std::vector<std::string> domainKeywords_;
    std::vector<std::string> domainWildcards_;
    std::vector<std::string> domainRegex_;
    // IP-CIDR / IP-CIDR6 / GEOIP / SRC-IP-CIDR: store as pair(value, noResolve)
    std::vector<std::pair<std::string, bool>> ipCIDRs_;
    std::vector<std::pair<std::string, bool>> ipCIDR6s_;
    std::vector<std::pair<std::string, bool>> geoIPs_;
    std::vector<std::pair<std::string, bool>> srcIPCIDRs_;

    // ================================================================
    // Existing data structures
    // ================================================================
    // Reverse-domain Trie for DOMAIN-SUFFIX O(k) containment
    std::unique_ptr<TrieNode> suffixTrieRoot_;

    // Aho-Corasick automaton for DOMAIN-KEYWORD O(n) multi-keyword matching
    std::unique_ptr<ACNode> acRoot_;
    std::vector<std::string> pendingKeywords_;
    mutable bool acBuilt_ = false;
    static constexpr size_t AC_REBUILD_THRESHOLD = 64;

    size_t totalCount_ = 0;

    // ================================================================
    // NEW data structures
    // ================================================================
    // Wildcard Pattern Trie root
    std::unique_ptr<WildcardNode> wildcardRoot_;

    // CIDR Radix Tree roots (separate for each noResolve flag)
    std::unique_ptr<CIDRRadixNode> cidrRoot_;
    std::unique_ptr<CIDRRadixNode> cidrNRRoot_;  // for no-resolve CIDRs

    // CIDR6 Radix Tree roots
    std::unique_ptr<CIDR6RadixNode> cidr6Root_;
    std::unique_ptr<CIDR6RadixNode> cidr6NRRoot_;

    // Double-Array Trie for suffix labels
    DoubleArrayTrie dat_;
    // Pending suffix labels to be added to DAT (for append-only rebuild)
    std::vector<std::string> pendingDATLabels_;
    static constexpr size_t DAT_REBUILD_THRESHOLD = 128;

    // Patricia Trie compaction trigger
    bool patriciaDirty_ = false;
    static constexpr size_t PATRICIA_COMPACT_THRESHOLD = 256;

    // ================================================================
    // Existing helper methods
    // ================================================================
    void insertIntoSuffixTrie(const std::string &value);
    bool checkSuffixTrie(const std::string_view &value) const;
    void insertIntoAC(const std::string &keyword);
    void rebuildAC();
    bool checkAC(const std::string &value) const;

    // Patricia Trie compaction (merge single-child nodes)
    void compactPatriciaTrie();
    bool tryMergeNode(TrieNode *node);

    // ================================================================
    // NEW helper methods
    // ================================================================
    // Wildcard Pattern Trie
    void insertIntoWildcardTrie(const std::string &value);
    bool checkWildcardTrie(const std::string &value) const;
    // Check wildcard pattern containment using the trie (for DOMAIN-WILDCARD query)
    bool checkWildcardContainment(const std::string &newValue) const;

    // CIDR Radix Tree
    void insertIntoCIDRRadix(const std::string &value, bool noResolve);
    bool checkCIDRRadix(uint32_t addr, uint8_t prefix, bool noResolve) const;

    // CIDR6 Radix Tree
    void insertIntoCIDR6Radix(const std::string &value, bool noResolve);
    bool checkCIDR6Radix(const uint8_t addr[16], uint8_t prefix, bool noResolve) const;

    // Double-Array Trie
    void rebuildDAT();
    bool checkDAT(const std::string_view &value) const;

    // Utility: split domain into reversed label list
    static std::vector<std::string> splitLabelsReversed(const std::string_view &value);
    // Utility: test if a label contains wildcard meta-chars (? or *)
    static bool hasWildcardMeta(const std::string &label);
    // Utility: extract IPv4 address and prefix from CIDR string
    static bool parseCIDRToRadix(const std::string &value, uint32_t &addr, uint8_t &prefix);
    // Utility: extract IPv6 address bytes from string
    static bool parseIPv6ToBytes(const std::string &value, uint8_t addr[16]);
};

std::string convertRuleset(const std::string &content, int type);
void rulesetToClash(YAML::Node &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules, bool new_field_name, bool dedup = true);
std::string rulesetToClashStr(YAML::Node &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules, bool new_field_name, bool dedup = true);
void rulesetToSurge(INIReader &base_rule, std::vector<RulesetContent> &ruleset_content_array, int surge_ver, bool overwrite_original_rules, const std::string& remote_path_prefix);
void rulesetToSingBox(rapidjson::Document &base_rule, std::vector<RulesetContent> &ruleset_content_array, bool overwrite_original_rules);

// Containment-based dedup for Clash classical rules (TYPE,VALUE format)
// Returns true if 'newKey' (TYPE,VALUE) is contained by any entry in 'index'
bool containmentCheck(const std::string &newKey, const ContainmentIndex &index);

#endif // RULECONVERT_H_INCLUDED
