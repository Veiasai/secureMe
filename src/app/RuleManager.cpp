#include <iostream>

#include "RuleManager.h"

namespace SAIL { namespace rule {

RuleManager::RuleManager(const std::string &configPath) {
    this->ctx = seccomp_init(SCMP_ACT_ALLOW);

    const YAML::Node config = YAML::LoadFile(configPath);
    const YAML::Node rules = config["rules"];

    this->ruleInit(rules);
}

void RuleManager::ruleInit(const YAML::Node &rules) {
    for (auto ruleNode : rules) {
        const int sysnum = ruleNode["sysnum"].as<int>();
        std::vector<struct scmp_arg_cmp> cmps;
        for (auto spec : ruleNode["specs"]) {
            const unsigned int paraIndex = spec["paraIndex"].as<unsigned int>();
            const std::string action = spec["action"].as<std::string>();
            const scmp_datum_t value = spec["value"].as<scmp_datum_t>();

            cmps.push_back((struct scmp_arg_cmp){paraIndex, this->cmpActionMap.at(action), value});
        }
        switch (cmps.size()) {
            case 0:
                seccomp_rule_add(this->ctx, SCMP_ACT_TRACE(0), sysnum, 0);
            case 1:
                seccomp_rule_add(this->ctx, SCMP_ACT_TRACE(0), sysnum, 1, cmps[0]);
            case 2:
                seccomp_rule_add(this->ctx, SCMP_ACT_TRACE(0), sysnum, 2, cmps[0], cmps[1]);
            case 3:
                seccomp_rule_add(this->ctx, SCMP_ACT_TRACE(0), sysnum, 3, cmps[0], cmps[1], cmps[2]);
            case 4:
                seccomp_rule_add(this->ctx, SCMP_ACT_TRACE(0), sysnum, 4, cmps[0], cmps[1], cmps[2], cmps[3]);
            case 5:
                seccomp_rule_add(this->ctx, SCMP_ACT_TRACE(0), sysnum, 5, cmps[0], cmps[1], cmps[2], cmps[3], cmps[4]);
            case 6:
                seccomp_rule_add(this->ctx, SCMP_ACT_TRACE(0), sysnum, 6, cmps[0], cmps[1], cmps[2], cmps[3], cmps[4], cmps[5]);
        }
    }
}

void RuleManager::applyRules() {
    seccomp_load(this->ctx);
}

}}
