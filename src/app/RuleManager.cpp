#include <iostream>

#include "RuleManager.h"
#include "BasicRule.h"

namespace SAIL { namespace rule {

RuleManager::RuleManager(const std::string &configPath) {
    this->ctxp.reset(new scmp_filter_ctx(seccomp_init(SCMP_ACT_ALLOW)));
    const YAML::Node config = YAML::LoadFile(configPath);

    this->modules["BasicRule"] = std::make_unique<BasicRule>(this->ctxp, config["rules"]);

    this->initRules();
}

void RuleManager::initRules() {
    for (auto it = this->modules.begin(); it != this->modules.end(); it++) {
        it->second->initRules();
    }
}

void RuleManager::applyRules() {
    seccomp_load(*this->ctxp);
}

RuleModule::RuleModule(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode) : ctxp(ctxp), ruleNode(ruleNode) {}

}}
