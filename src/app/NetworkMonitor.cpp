#include "NetworkMonitor.h"

namespace SAIL { namespace rule {

NetworkMonitor::NetworkMonitor(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode, const std::shared_ptr<util::Utils> &up) : 
    RuleModule(ctxp, ruleNode, up) 
{
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
 
    spdlog::info("init NetworkMonitor module");
    this->initRules();
}

void NetworkMonitor::initRules() {
    seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(SM_EVM_CONNECT), SCMP_SYS(connect), 0);
}

bool NetworkMonitor::check(const long eventMsg, const user_regs_struct &regs, const int tid) {
    // connect-caused trap
    const int size = regs.rdx;
    spdlog::info("sockaddr length: {}", size);
    char *buf = new char(size);
    this->up->readBytesFrom(tid, (char *)regs.rsi, buf, size);
    const struct sockaddr *sa = reinterpret_cast<struct sockaddr *>(buf);

    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *sa_in = reinterpret_cast<const struct sockaddr_in *>(sa);
        const in_addr_t ipv4 = sa_in->sin_addr.s_addr;
        spdlog::debug("NetworkMonitor: catch connect {}", ipv4);

        char addrBuf[20];
        inet_ntop(AF_INET, &(ipv4), addrBuf, INET_ADDRSTRLEN);
        spdlog::info("check ipv4: {}", std::string(addrBuf));

        if (this->ipv4WhiteList.find(ipv4) != this->ipv4WhiteList.end()) {
            return true;
        }
        spdlog::critical("connect to {}, which is not in whitelist", std::string(addrBuf));
        return false;
    }
}

} // namespace rule
} // namespace SAIL