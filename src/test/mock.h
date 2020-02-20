#pragma once

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "../app/RuleManager.h"
#include "../app/BasicRule.h"
#include "../app/FileWhitelist.h"
#include "../app/NetworkMonitor.h"

namespace SAIL { namespace test {
    
using namespace testing;

class MockRuleManager : public RuleManager {

};

class MockBasicRule : public BasicRule {

};

class MockFileWhitelist : public FileWhitelist {

};

class MockNetworkMonitor : public NetworkMonitor {

};

}}