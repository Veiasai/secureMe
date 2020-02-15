#pragma once

#include <string>
#include <memory>

#include <seccomp.h>
#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

#include "macro.h"
#include "Utils.h"

namespace SAIL { namespace rule {

class RuleModule;

class RuleManager
{
private:
    std::shared_ptr<scmp_filter_ctx> ctxp;
    std::map<std::string, std::shared_ptr<RuleModule>> modules;
    const std::shared_ptr<util::Utils> up;

public:
    RuleManager(const std::string &configPath, const std::shared_ptr<util::Utils> &up);
    void initRules();
    void applyRules() const;
    std::shared_ptr<RuleModule> getModule(const std::string &moduleName);
};

class RuleModule
{
protected:
    std::shared_ptr<scmp_filter_ctx> ctxp;
    const YAML::Node ruleNode;
    const std::shared_ptr<util::Utils> up;

    // connect seccomp macro with our config yaml syntax
    const std::map<std::string, enum scmp_compare> cmpActionMap = {
        {"notEqual", SCMP_CMP_NE},
        {"less", SCMP_CMP_LT},
        {"notGreater", SCMP_CMP_LE},
        {"equal", SCMP_CMP_EQ},
        {"notLess", SCMP_CMP_GE},
        {"greater", SCMP_CMP_GT}
    };

    const std::map<unsigned int, std::string> regIndexMap = {
        {1, "rdi"}, {2, "rsi"}, {3, "rdx"}, {4, "rcx"}, {5, "r8"}, {6, "r9"}
    };

public:
    RuleModule(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode, const std::shared_ptr<util::Utils> &up);
    virtual void initRules() = 0;
};

}}