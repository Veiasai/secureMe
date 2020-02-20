#include "RuleManager.h"
#include "BasicRule.h"
#include "FileWhitelist.h"
#include "NetworkMonitor.h"

namespace SAIL { namespace rule {

RuleManager::RuleManager(const YAML::Node &config, const std::shared_ptr<util::Utils> &up) : up(up) {
    this->ctxp.reset(new scmp_filter_ctx(seccomp_init(SCMP_ACT_ALLOW)));

    // order matters
    this->modules[SM_BASIC_RULE] = std::make_shared<BasicRule>(this->ctxp, config["rules"], up);
    this->modules[SM_FILE_WHITELIST] = std::make_shared<FileWhitelist>(this->ctxp, config["plugins"]["filewhitelist"], up);
    this->modules[SM_NETWORK_MONITOR] = std::make_shared<NetworkMonitor>(this->ctxp, config["plugins"]["network"], up);
}

void RuleManager::applyRules() const {
    seccomp_load(*this->ctxp);
}

std::shared_ptr<RuleModule> RuleManager::getModule(const std::string &moduleName) {
    // check module exists
    return this->modules[moduleName];
}

RuleModule::RuleModule(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode, const std::shared_ptr<util::Utils> &up) : ctxp(ctxp), ruleNode(ruleNode), up(up) {}

} // namespace rule
} // namespace SAIL
