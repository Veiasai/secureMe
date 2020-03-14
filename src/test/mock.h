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
    MOCK_METHOD(std::shared_ptr<RuleModule>, getModule, (const long eventMsg), (override));
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
    MOCK_METHOD(int, getRegs, (int tid, user_regs_struct *regs), (override));
    MOCK_METHOD(int, getParaInfo, (int tid, const int sysnum, const int paraIndex, const user_regs_struct &regs, ParaInfo &paraInfo), (override));
    MOCK_METHOD(int, readStrFrom, (int tid, const char *p, char *buf, size_t s), (override));
    MOCK_METHOD(int, readBytesFrom, (int tid, const char *p, char *buf, size_t s), (override));
    MOCK_METHOD(bool, isEvent, (const int status, const int event), (override));
    MOCK_METHOD(bool, hasEvent, (const int status), (override));
    MOCK_METHOD(long, getEventMsg, (const int tid), (override));
    MOCK_METHOD(void, killTarget, (const int tid), (override));
};
}}