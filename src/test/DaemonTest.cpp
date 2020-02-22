#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "mock.h"
#include "../app/Daemon.h"
#include "../app/macro.h"

namespace SAIL { namespace test {

class DaemonFixture : public ::testing::Test {
public:
    pid_t child;
    std::shared_ptr<MockRuleManager> rulemgr;
    std::shared_ptr<MockUtils> up;
    std::shared_ptr<MockBasicRule> basicRule;
    std::shared_ptr<MockFileWhitelist> fileWhitelist;
    std::shared_ptr<MockNetworkMonitor> networkMonitor;

    DaemonFixture() {
        this->child = 0;
        this->rulemgr = std::make_shared<MockRuleManager>();
        this->up = std::make_shared<MockUtils>();
        this->basicRule = std::make_shared<MockBasicRule>();
        this->fileWhitelist = std::make_shared<MockFileWhitelist>();
        this->networkMonitor = std::make_shared<MockNetworkMonitor>();
    }

    void SetUp() {}

    void TearDown() {}
};

TEST_F(DaemonFixture, HandleBasicRule) {
    core::Daemon daemon(this->child, this->rulemgr, this->up);
    user_regs_struct regs;
    const long eventMsg = 101;

    EXPECT_CALL(*this->up, getRegs(this->child, _))
        .Times(1)
        .WillOnce(SetArgReferee<1>(regs));

    EXPECT_CALL(*this->rulemgr, getModule(SM_BASIC_RULE))
        .Times(1)
        .WillOnce(Return(ByMove(this->basicRule)));

    EXPECT_CALL(*this->basicRule, check(eventMsg, _, this->child))
        .Times(1)
        .WillOnce(Return(true));

    daemon.handleEvent(eventMsg, this->child);
}

TEST_F(DaemonFixture, HandleFileWhitelist) {
    core::Daemon daemon(this->child, this->rulemgr, this->up);
    user_regs_struct regs;
    const long eventMsg = 10;

    EXPECT_CALL(*this->up, getRegs(this->child, _))
        .Times(1)
        .WillOnce(SetArgReferee<1>(regs));

    EXPECT_CALL(*this->rulemgr, getModule(SM_FILE_WHITELIST))
        .Times(1)
        .WillOnce(Return(ByMove(this->fileWhitelist)));

    EXPECT_CALL(*this->fileWhitelist, check(eventMsg, _, this->child))
        .Times(1)
        .WillOnce(Return(true));

    daemon.handleEvent(eventMsg, this->child);
}

TEST_F(DaemonFixture, HandleNetworkMonitor) {
    core::Daemon daemon(this->child, this->rulemgr, this->up);
    user_regs_struct regs;
    const long eventMsg = 20;

    EXPECT_CALL(*this->up, getRegs(this->child, _))
        .Times(1)
        .WillOnce(SetArgReferee<1>(regs));

    EXPECT_CALL(*this->rulemgr, getModule(SM_NETWORK_MONITOR))
        .Times(1)
        .WillOnce(Return(ByMove(this->networkMonitor)));

    EXPECT_CALL(*this->networkMonitor, check(eventMsg, _, this->child))
        .Times(1)
        .WillOnce(Return(true));

    daemon.handleEvent(eventMsg, this->child);
}

}}