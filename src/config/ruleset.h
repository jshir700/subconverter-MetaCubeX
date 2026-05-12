#ifndef RULESET_H_INCLUDED
#define RULESET_H_INCLUDED

#include "def.h"

enum class RulesetType
{
    SurgeRuleset,
    QuantumultX,
    ClashDomain,
    ClashIpCidr,
    ClashClassic
};

struct RulesetConfig
{
    String Group;
    //RulesetType Type = RulesetType::SurgeRuleset;
    String Url;
    Integer Interval = 0;
    String UserAgent;
    String Proxy;
    bool Provider = false;
    bool provider_explicit = false;
    bool provider_override = false;
    bool operator==(const RulesetConfig &r) const
    {
        return Group == r.Group && Url == r.Url && Interval == r.Interval;
    }
};

using RulesetConfigs = std::vector<RulesetConfig>;

#endif // RULESET_H_INCLUDED
