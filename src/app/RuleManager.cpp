#include "RuleManager.h"
#include "BasicRule.h"
#include "FileWhitelist.h"
#include "NetworkMonitor.h"

namespace SAIL { namespace rule {

RuleManager::RuleManager(const YAML::Node &config, const std::shared_ptr<util::Utils> &up) : up(up) {
    this->ctxp.reset(new scmp_filter_ctx(seccomp_init(SCMP_ACT_ALLOW)));

    // order matters
    if (config["rules"].IsDefined()) {
        spdlog::info("BasicRule Defined");
        this->modules[SM_BASIC_RULE] = std::make_shared<BasicRule>(this->ctxp, config["rules"], up);
    }
    if (config["plugins"].IsDefined() && config["plugins"]["filewhitelist"].IsDefined()) {
        spdlog::info("FileWhitelist Defined");
        this->modules[SM_FILE_WHITELIST] = std::make_shared<FileWhitelist>(this->ctxp, config["plugins"]["filewhitelist"], up);
    }
    if (config["plugins"].IsDefined() && config["plugins"]["network"].IsDefined()) {
        spdlog::info("NetworkMonitor Defined");
        this->modules[SM_NETWORK_MONITOR] = std::make_shared<NetworkMonitor>(this->ctxp, config["plugins"]["network"], up);
    }
}

void RuleManager::applyRules() const {
    seccomp_load(*this->ctxp);
}

std::shared_ptr<RuleModule> RuleManager::getModule(const long eventMsg) {
    if (SM_IN_BASIC_RULE(eventMsg)) {
        return this->modules[SM_BASIC_RULE];
    }
    else if (SM_IN_FILE_WHITELIST(eventMsg)) {
        return this->modules[SM_FILE_WHITELIST];
    }
    else if (SM_IN_NETWORK_MONITOR(eventMsg)) {
        return this->modules[SM_NETWORK_MONITOR];
    }
    else {
        assert(0);
    }
}

int RuleManager::handleEvent(const long eventMsg, const pid_t tid, const user_regs_struct &regs) {
    std::shared_ptr<rule::RuleModule> ruleModule = this->getModule(eventMsg);
    bool doPassCheck = ruleModule->check(eventMsg, regs, tid);

    if (!doPassCheck) {
        return 1;
    }
    return 0;
}

RuleModule::RuleModule(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode, const std::shared_ptr<util::Utils> &up) : ctxp(ctxp), ruleNode(ruleNode), up(up) {}

} // namespace rule
} // namespace SAIL
