#pragma once

#include <regex>
#include <fcntl.h>                                            

#include "RuleManager.h"

namespace SAIL { namespace rule {

class FileWhitelist : public RuleModule
{
private:
    std::vector<std::regex> regFiles;

public:
    FileWhitelist() {}
    FileWhitelist(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode, const std::shared_ptr<util::Utils> &up);
    virtual void initRules() override;
    virtual bool check(const long eventMsg, const user_regs_struct &regs, const int tid) override;
};

} // namespace rule
} // namespace SAIL