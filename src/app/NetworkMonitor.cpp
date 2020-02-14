#include "NetworkMonitor.h"

namespace SAIL { namespace rule {

NetworkMonitor::NetworkMonitor(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode) : RuleModule(ctxp, ruleNode) {
    for (const auto &ipStr : ruleNode["ipv4"].as<std::vector<std::string>>()) {
        in_addr_t ipv4 = 0;
        int rc = inet_pton(AF_INET, ipStr.c_str(), &(ipv4));
        // spdlog::info("ip: {}", ipStr);
        // spdlog::info("in_addr: {}", ipv4);

        if (rc <= 0) {
            spdlog::critical("NetworkMonitor plugin: Invalid ipv4 address");
            exit(-1);
        }
        this->ipv4WhiteList.insert(ipv4);
    }
}

void NetworkMonitor::initRules() {
    seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(EVM_CONNECT), SCMP_SYS(connect), 0);
}

bool NetworkMonitor::checkIPv4(const in_addr_t &ipv4) {
    char addrBuf[20];
    inet_ntop(AF_INET, &(ipv4), addrBuf, INET_ADDRSTRLEN);
    // spdlog::info("check ipv4: {}", std::string(addrBuf));

    if (this->ipv4WhiteList.find(ipv4) != this->ipv4WhiteList.end()) {
        return true;
    }
    return false;
}

}}