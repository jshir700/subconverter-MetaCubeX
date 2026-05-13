#include <string>
#include <cstdarg>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

/*
#ifdef USE_STD_REGEX
#include <regex>
#else
*/
#include <jpcre2.hpp>
using jp = jpcre2::select<char>;
//#endif // USE_STD_REGEX

#include "regexp.h"

// PCRE2 regex compilation cache
// Avoids recompiling the same pattern on every regFind/regMatch/regReplace call
namespace {
    struct RegexCache {
        // Main pattern cache: pattern -> compiled regex
        std::unordered_map<std::string, jp::Regex> cache;
        // Modifier suffix cache: pattern|modifier -> compiled regex
        std::unordered_map<std::string, jp::Regex> modifierCache;
        mutable std::shared_mutex mutex;

        static std::string modifierKey(const std::string &pattern, const std::string &modifiers) {
            return pattern + "|" + modifiers;
        }

        jp::Regex* getOrCompile(const std::string &pattern, const std::string &modifiers, uint32_t options) {
            std::string key = modifierKey(pattern, modifiers);

            // Fast path: read-lock lookup
            {
                std::shared_lock<std::shared_mutex> lock(mutex);
                auto it = modifierCache.find(key);
                if (it != modifierCache.end())
                    return &it->second;
            }

            // Slow path: compile (under write lock)
            std::unique_lock<std::shared_mutex> lock(mutex);
            auto it = modifierCache.find(key);
            if (it != modifierCache.end())
                return &it->second;

            jp::Regex reg;
            reg.setPattern(pattern).addModifier(modifiers.c_str()).addPcre2Option(options).compile();
            if (!reg) {
                // Store invalid regex to avoid recompilation attempts
                modifierCache[key] = std::move(reg);
                return nullptr;
            }

            auto result = &modifierCache.emplace(key, std::move(reg)).first->second;
            // Keep cache bounded: if too large, clear it
            if (modifierCache.size() > 1024) {
                modifierCache.clear();
                // Re-insert this entry
                jp::Regex reg2;
                reg2.setPattern(pattern).addModifier(modifiers.c_str()).addPcre2Option(options).compile();
                modifierCache[key] = std::move(reg2);
                result = &modifierCache.find(key)->second;
            }
            return result;
        }
    };

    RegexCache& getRegexCache() {
        static RegexCache instance;
        return instance;
    }

    uint32_t pcre2_options(bool is_utf) {
        uint32_t opts = PCRE2_ALT_BSUX;
        if (is_utf) opts |= PCRE2_UTF;
        return opts;
    }
} // anonymous namespace

/*
#ifdef USE_STD_REGEX
bool regValid(const std::string &reg)
...
#else
*/
bool regMatch(const std::string &src, const std::string &match)
{
    auto *reg = getRegexCache().getOrCompile(match, "m", PCRE2_ANCHORED|PCRE2_ENDANCHORED|PCRE2_UTF);
    if (!reg || !(*reg))
        return false;
    return reg->match(src, "g");
}

bool regFind(const std::string &src, const std::string &match)
{
    auto *reg = getRegexCache().getOrCompile(match, "m", PCRE2_UTF|PCRE2_ALT_BSUX);
    if (!reg || !(*reg))
        return false;
    return reg->match(src, "g");
}

std::string regReplace(const std::string &src, const std::string &match, const std::string &rep, bool global, bool multiline)
{
    auto *reg = getRegexCache().getOrCompile(match, multiline ? "m" : "", PCRE2_UTF|PCRE2_MULTILINE|PCRE2_ALT_BSUX);
    if (!reg || !(*reg))
        return src;
    return reg->replace(src, rep, global ? "gEx" : "Ex");
}

bool regValid(const std::string &reg)
{
    jp::Regex r;
    r.setPattern(reg).addPcre2Option(PCRE2_UTF|PCRE2_ALT_BSUX).compile();
    return !!r;
}

int regGetMatch(const std::string &src, const std::string &match, size_t group_count, ...)
{
    auto result = regGetAllMatch(src, match, false);
    if(result.empty())
        return -1;
    va_list vl;
    va_start(vl, group_count);
    size_t index = 0;
    while(group_count)
    {
        std::string* arg = va_arg(vl, std::string*);
        if(arg != nullptr)
            *arg = std::move(result[index]);
        index++;
        group_count--;
        if(result.size() <= index)
            break;
    }
    va_end(vl);
    return 0;
}

std::vector<std::string> regGetAllMatch(const std::string &src, const std::string &match, bool group_only)
{
    auto *reg = getRegexCache().getOrCompile(match, "m", PCRE2_UTF|PCRE2_ALT_BSUX);
    if (!reg || !(*reg))
        return {};

    jp::VecNum vec_num;
    jp::RegexMatch rm;
    size_t count = rm.setRegexObject(reg).setSubject(src).setNumberedSubstringVector(&vec_num).setModifier("gm").match();
    std::vector<std::string> result;
    if(!count)
        return result;
    size_t begin = 0;
    if(group_only)
        begin = 1;
    size_t index = begin, match_index = 0;
    while(true)
    {
        if(vec_num.size() <= match_index)
            break;
        if(vec_num[match_index].size() <= index)
        {
            match_index++;
            index = begin;
            continue;
        }
        result.push_back(std::move(vec_num[match_index][index]));
        index++;
    }
    return result;
}

//#endif // USE_STD_REGEX

std::string regTrim(const std::string &src)
{
    return regReplace(src, R"(^\s*([\s\S]*)\s*$)", "$1", false, false);
}
