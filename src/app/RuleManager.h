#pragma once

#include <string>
#include <memory>

#include <seccomp.h>
#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

namespace SAIL { namespace rule {

class RuleModule;

class RuleManager
{
private:
    std::shared_ptr<scmp_filter_ctx> ctxp;
    std::map<std::string, std::unique_ptr<RuleModule>> modules;

public:
    RuleManager(const std::string &configPath);
    void initRules();
    void applyRules() const;
};

class RuleModule
{
protected:
    std::shared_ptr<scmp_filter_ctx> ctxp;
    const YAML::Node ruleNode;

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
    RuleModule(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode);
    virtual void initRules() = 0;
};

}}