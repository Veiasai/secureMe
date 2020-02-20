#pragma once

#include <regex>

#include "RuleManager.h"

namespace SAIL { namespace rule {

class BasicRule : public RuleModule
{
private:
    struct ptrace_arg_cmp {
        unsigned int paraIndex;
        std::string action;
        int intValue;
        std::vector<int> bytesValue;
        std::string strValue;

        ptrace_arg_cmp(const unsigned int paraIndex, const std::string &action, const int intValue) : 
            paraIndex(paraIndex), action(action), intValue(intValue) {}
        ptrace_arg_cmp(const unsigned int paraIndex, const std::string &action, const std::vector<int> &bytesValue) : 
            paraIndex(paraIndex), action(action), bytesValue(bytesValue) {}
        ptrace_arg_cmp(const unsigned int paraIndex, const std::string &action, const std::string &strValue) : 
            paraIndex(paraIndex), action(action), strValue(strValue) {}
    };

    struct Rule {
        int sysnum;
        int id;
        std::vector<struct scmp_arg_cmp> specs;
        std::vector<struct ptrace_arg_cmp> pSpecs;
        bool needExtraCheck; // if action is matchBytes or matchRe, which seccomp cannot handle, need extra check with ptrace

        Rule(const int sysnum, const int id, const std::vector<struct scmp_arg_cmp> &specs) : 
            sysnum(sysnum), id(id), specs(specs), needExtraCheck(false) {}
        Rule(const int sysnum, const int id, const std::vector<struct ptrace_arg_cmp> &pSpecs) : 
            sysnum(sysnum), id(id), pSpecs(pSpecs), needExtraCheck(true) {}
    };

    std::vector<Rule> rules;

public:
    BasicRule(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode, const std::shared_ptr<util::Utils> &up);
    void initRules() override;
    bool check(const long eventMsg, const user_regs_struct &regs, const int tid) override;
    bool matchRe(const struct ptrace_arg_cmp &pSpec, const unsigned long long reg, const int tid);
    bool matchBytes(const struct ptrace_arg_cmp &pSpec, const unsigned long long reg, const int tid);
};

} // namespace rule
} // namespace SAIL