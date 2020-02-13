#include "BasicRule.h"

namespace SAIL { namespace rule {

BasicRule::BasicRule(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode) : RuleModule(ctxp, ruleNode) {}

void BasicRule::initRules() {
    for (auto rule : this->ruleNode) {
        const int sysnum = rule["sysnum"].as<int>();
        std::vector<struct scmp_arg_cmp> cmps;
        for (auto spec : rule["specs"]) {
            const unsigned int paraIndex = spec["paraIndex"].as<unsigned int>();
            const std::string action = spec["action"].as<std::string>();
            const scmp_datum_t value = spec["value"].as<scmp_datum_t>();

            cmps.push_back((struct scmp_arg_cmp){paraIndex, this->cmpActionMap.at(action), value});
        }
        switch (cmps.size()) {
            case 0:
                seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(0), sysnum, 0);
            case 1:
                seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(0), sysnum, 1, cmps[0]);
            case 2:
                seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(0), sysnum, 2, cmps[0], cmps[1]);
            case 3:
                seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(0), sysnum, 3, cmps[0], cmps[1], cmps[2]);
            case 4:
                seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(0), sysnum, 4, cmps[0], cmps[1], cmps[2], cmps[3]);
            case 5:
                seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(0), sysnum, 5, cmps[0], cmps[1], cmps[2], cmps[3], cmps[4]);
            case 6:
                seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(0), sysnum, 6, cmps[0], cmps[1], cmps[2], cmps[3], cmps[4], cmps[5]);
        }
    }
}

}}