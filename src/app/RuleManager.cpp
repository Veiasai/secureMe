#include <iostream>

#include "RuleManager.h"

namespace SAIL { namespace rule {

RuleManager::RuleManager(const std::string &configPath) {
    const YAML::Node config = YAML::LoadFile(configPath);
}

}}
