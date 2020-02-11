#pragma once

#include <string>

#include <yaml-cpp/yaml.h>

namespace SAIL { namespace rule {

class RuleManager
{
public:
    RuleManager(const std::string &configPath);
};

}}