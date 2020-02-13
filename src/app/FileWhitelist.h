#pragma once

#include "RuleManager.h"

namespace SAIL { namespace rule {

class FileWhitelist : public RuleModule
{
public:
    FileWhitelist(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode);
    void initRules() override;
    std::string handleEscape(std::string regStr);
};

} // namespace rule
} // namespace SAIL