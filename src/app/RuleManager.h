#pragma once

#include <string>

#include <seccomp.h>
#include <yaml-cpp/yaml.h>

namespace SAIL { namespace rule {

class RuleManager
{
private:
    scmp_filter_ctx ctx;

    // connect seccomp macro with our config yaml syntax
    const std::map<std::string, enum scmp_compare> cmpActionMap = {
        {"notEqual", SCMP_CMP_NE},
        {"less", SCMP_CMP_LT},
        {"notGreater", SCMP_CMP_LE},
        {"equal", SCMP_CMP_EQ},
        {"notLess", SCMP_CMP_GE},
        {"greater", SCMP_CMP_GT}
    };

public:
    RuleManager(const std::string &configPath);
    void ruleInit(const YAML::Node &yaml);
    void applyRules();
};

}}