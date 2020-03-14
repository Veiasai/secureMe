#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "mock.h"

namespace SAIL { namespace test {

class NetworkMonitorFixture : public ::testing::Test {
public:
    std::shared_ptr<scmp_filter_ctx> ctxp;
    std::shared_ptr<MockUtils> up;

    NetworkMonitorFixture() {
        this->ctxp.reset(new scmp_filter_ctx(seccomp_init(SCMP_ACT_ALLOW)));
        this->up = std::make_shared<MockUtils>();
    }

    void SetUp() {}

    void TearDown() {}
};

TEST_F(NetworkMonitorFixture, InWhitelist) {
    const YAML::Node ruleNode = YAML::Load("{ ipv4: [1.1.1.1, 2.2.2.2] }");
    NetworkMonitor networkMonitor(this->ctxp, ruleNode, this->up);

    user_regs_struct regs;
    regs.rdx = 16;
    int tid;

    const char *ip = "1.1.1.1";
    struct sockaddr_in sa_in;
    sa_in.sin_family = AF_INET;
    inet_aton(ip, &(sa_in.sin_addr));
    const char *buf = reinterpret_cast<char *>(&sa_in);

    EXPECT_CALL(*this->up, readBytesFrom(tid, (char *)regs.rdi, _, regs.rdx))
        .Times(1)
        .WillOnce(SetArrayArgument<2>(buf, buf + 17));

    bool doPassCheck = networkMonitor.check(SM_EVM_CONNECT, regs, tid);
    ASSERT_TRUE(doPassCheck);
}

TEST_F(NetworkMonitorFixture, NotInWhitelist) {
    const YAML::Node ruleNode = YAML::Load("{ ipv4: [1.1.1.1, 2.2.2.2] }");
    NetworkMonitor networkMonitor(this->ctxp, ruleNode, this->up);

    user_regs_struct regs;
    regs.rdx = 16;
    int tid;

    const char *ip = "3.3.3.2";
    struct sockaddr_in sa_in;
    sa_in.sin_family = AF_INET;
    inet_aton(ip, &(sa_in.sin_addr));
    const char *buf = reinterpret_cast<char *>(&sa_in);

    EXPECT_CALL(*this->up, readBytesFrom(tid, (char *)regs.rdi, _, regs.rdx))
        .Times(1)
        .WillOnce(SetArrayArgument<2>(buf, buf + 17));

    bool doPassCheck = networkMonitor.check(SM_EVM_CONNECT, regs, tid);
    ASSERT_FALSE(doPassCheck);
}

} // namespace test
} // namespace SAIL