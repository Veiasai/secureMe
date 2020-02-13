#pragma once

#include "RuleManager.h"

namespace SAIL { namespace rule {

class BasicRule : public RuleModule
{
public:
    BasicRule(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode);
    void initRules() override;
};

} // namespace rule
} // namespace SAIL