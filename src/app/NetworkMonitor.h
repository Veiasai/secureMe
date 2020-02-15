#pragma once

#include <set>
#include <arpa/inet.h>

#include "RuleManager.h"

namespace SAIL { namespace rule {

class NetworkMonitor : public RuleModule
{
private:
    std::set<in_addr_t> ipv4WhiteList;

public:
    NetworkMonitor(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode, const std::shared_ptr<util::Utils> &up);
    void initRules() override;
    bool checkIPv4(const in_addr_t &ipv4);
};

}}