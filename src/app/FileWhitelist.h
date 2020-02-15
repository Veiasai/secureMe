#pragma once

#include <regex>

#include "RuleManager.h"

namespace SAIL { namespace rule {

class FileWhitelist : public RuleModule
{
private:
    std::vector<std::regex> regFiles;

public:
    FileWhitelist(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode, const std::shared_ptr<util::Utils> &up);
    void initRules() override;
    bool checkFile(const std::string &filename);
};

} // namespace rule
} // namespace SAIL