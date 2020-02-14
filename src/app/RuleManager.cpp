#include <iostream>

#include "RuleManager.h"
#include "BasicRule.h"
#include "FileWhitelist.h"

namespace SAIL { namespace rule {

RuleManager::RuleManager(const std::string &configPath) {
    this->ctxp.reset(new scmp_filter_ctx(seccomp_init(SCMP_ACT_ALLOW)));
    const YAML::Node config = YAML::LoadFile(configPath);

    this->modules["BasicRule"] = std::make_shared<BasicRule>(this->ctxp, config["rules"]);
    this->modules["FileWhitelist"] = std::make_shared<FileWhitelist>(this->ctxp, config["plugins"]["filewhitelist"]);

    this->initRules();
}

void RuleManager::initRules() {
    for (auto it = this->modules.begin(); it != this->modules.end(); it++) {
        it->second->initRules();
    }
}

void RuleManager::applyRules() const {
    seccomp_load(*this->ctxp);
}

std::shared_ptr<RuleModule> RuleManager::getModule(const std::string &moduleName) {
    // check module exists
    return this->modules[moduleName];
}

RuleModule::RuleModule(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode) : ctxp(ctxp), ruleNode(ruleNode) {}

}}
