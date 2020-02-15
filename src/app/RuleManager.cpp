#include <iostream>

#include "RuleManager.h"
#include "BasicRule.h"
#include "FileWhitelist.h"
#include "NetworkMonitor.h"

namespace SAIL { namespace rule {

RuleManager::RuleManager(const std::string &configPath, const std::shared_ptr<util::Utils> &up) : up(up) {
    this->ctxp.reset(new scmp_filter_ctx(seccomp_init(SCMP_ACT_ALLOW)));
    const YAML::Node config = YAML::LoadFile(configPath);

    // order matters
    this->modules["BasicRule"] = std::make_shared<BasicRule>(this->ctxp, config["rules"], up);
    this->modules["FileWhitelist"] = std::make_shared<FileWhitelist>(this->ctxp, config["plugins"]["filewhitelist"], up);
    this->modules["NetworkMonitor"] = std::make_shared<NetworkMonitor>(this->ctxp, config["plugins"]["network"], up);
}

void RuleManager::applyRules() const {
    seccomp_load(*this->ctxp);
}

std::shared_ptr<RuleModule> RuleManager::getModule(const std::string &moduleName) {
    // check module exists
    return this->modules[moduleName];
}

RuleModule::RuleModule(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode, const std::shared_ptr<util::Utils> &up) : 
    ctxp(ctxp), ruleNode(ruleNode), up(up) {}

}}
