#pragma once

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "../app/RuleManager.h"
#include "../app/BasicRule.h"
#include "../app/FileWhitelist.h"
#include "../app/NetworkMonitor.h"
#include "../app/Utils.h"

namespace SAIL { namespace test {
    
using namespace testing;
using namespace rule;
using namespace util;

class MockRuleManager : public RuleManager {
public:
    MOCK_METHOD(std::shared_ptr<RuleModule>, getModule, (const std::string &moduleName), (override));
};

class MockBasicRule : public BasicRule {
public:
    MOCK_METHOD(bool, check, (const long eventMsg, const user_regs_struct &regs, const int tid), (override));
};

class MockFileWhitelist : public FileWhitelist {
public:
    MOCK_METHOD(bool, check, (const long eventMsg, const user_regs_struct &regs, const int tid), (override));
};

class MockNetworkMonitor : public NetworkMonitor {
public:
    MOCK_METHOD(bool, check, (const long eventMsg, const user_regs_struct &regs, const int tid), (override));
};

class MockUtils : public Utils {
public:
    MOCK_METHOD(int, getRegs, (int tid, user_regs_struct &regs), (override));
};
}}