#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "mock.h"

namespace SAIL { namespace test {

class BasicRuleFixture : public ::testing::Test {
public:
    std::shared_ptr<scmp_filter_ctx> ctxp;
    std::shared_ptr<MockUtils> up;

    BasicRuleFixture() {
        this->ctxp.reset(new scmp_filter_ctx(seccomp_init(SCMP_ACT_ALLOW)));
        this->up = std::make_shared<MockUtils>();
    }

    void SetUp() {}

    void TearDown() {}
};

TEST_F(BasicRuleFixture, MatchReSimple) {
    YAML::Node ruleNode;
    ruleNode[0]["sysnum"] = 1;
    ruleNode[0]["id"] = 1;
    ruleNode[0]["specs"].push_back(YAML::Load("{ paraIndex: 1, action: matchRe, value: abc }"));

    BasicRule basicRule(this->ctxp, ruleNode, this->up);
    user_regs_struct regs;
    int tid;

    // case 1: pass
    // suppress warning that forbids converting a string constant to char *
    char *actualStr = const_cast<char *>("ab");
    EXPECT_CALL(*this->up, readStrFrom(tid, (char *)regs.rdi, _, SM_MAX_STRING_SIZE))
        .Times(1)
        .WillOnce(SetArrayArgument<2>(actualStr, actualStr + strlen(actualStr) + 1));

    bool doPassCheck = basicRule.check(SM_EVM_BASIC_BASE, regs, tid);
    ASSERT_TRUE(doPassCheck);

    // case 2: not pass
    actualStr = const_cast<char *>("abc");
    EXPECT_CALL(*this->up, readStrFrom(tid, (char *)regs.rdi, _, SM_MAX_STRING_SIZE))
        .Times(1)
        .WillOnce(SetArrayArgument<2>(actualStr, actualStr + strlen(actualStr) + 1));

    doPassCheck = basicRule.check(SM_EVM_BASIC_BASE, regs, tid);
    ASSERT_FALSE(doPassCheck);

    // case 3: pass
    actualStr = const_cast<char *>("abcd");
    EXPECT_CALL(*this->up, readStrFrom(tid, (char *)regs.rdi, _, SM_MAX_STRING_SIZE))
        .Times(1)
        .WillOnce(SetArrayArgument<2>(actualStr, actualStr + strlen(actualStr) + 1));

    doPassCheck = basicRule.check(SM_EVM_BASIC_BASE, regs, tid);
    ASSERT_TRUE(doPassCheck);
}

// complex means using regular expression
TEST_F(BasicRuleFixture, MatchReComplex) {
    YAML::Node ruleNode;
    ruleNode[0]["sysnum"] = 1;
    ruleNode[0]["id"] = 1;
    ruleNode[0]["specs"].push_back(YAML::Load("{ paraIndex: 1, action: matchRe, value: a.* }"));

    BasicRule basicRule(this->ctxp, ruleNode, this->up);
    user_regs_struct regs;
    int tid;

    // case 1: not pass
    char *actualStr = const_cast<char *>("abc");
    EXPECT_CALL(*this->up, readStrFrom(tid, (char *)regs.rdi, _, SM_MAX_STRING_SIZE))
        .Times(1)
        .WillOnce(SetArrayArgument<2>(actualStr, actualStr + strlen(actualStr) + 1));

    bool doPassCheck = basicRule.check(SM_EVM_BASIC_BASE, regs, tid);
    ASSERT_FALSE(doPassCheck);

    // case 2: pass
    actualStr = const_cast<char *>("tbc");
    EXPECT_CALL(*this->up, readStrFrom(tid, (char *)regs.rdi, _, SM_MAX_STRING_SIZE))
        .Times(1)
        .WillOnce(SetArrayArgument<2>(actualStr, actualStr + strlen(actualStr) + 1));

    doPassCheck = basicRule.check(SM_EVM_BASIC_BASE, regs, tid);
    ASSERT_TRUE(doPassCheck);
}

TEST_F(BasicRuleFixture, MatchBytes) {
    const int sysnum = 1;
    YAML::Node ruleNode;
    ruleNode[0]["sysnum"] = sysnum;
    ruleNode[0]["id"] = 1;
    ruleNode[0]["specs"].push_back(
        YAML::Load("{ paraIndex: 1, action: matchBytes, value: [0x61, 0x62] }")
    );  // ['a', 'b']

    BasicRule basicRule(this->ctxp, ruleNode, this->up);
    user_regs_struct regs;
    int tid;

    // case 1: not pass
    util::ParaInfo paraInfo;
    paraInfo.size = 3;
    const unsigned char actualBytes[3] = { 0x61, 0x62, 0x63 };
    paraInfo.value = reinterpret_cast<long>(actualBytes);

    EXPECT_CALL(*this->up, getParaInfo(tid, sysnum, 1, _, _))
        .Times(1)
        .WillOnce(SetArgReferee<4>(paraInfo));

    bool doPassCheck = basicRule.check(SM_EVM_BASIC_BASE, regs, tid);
    ASSERT_FALSE(doPassCheck);

    // case 2: pass
    paraInfo.size = 1;
    const unsigned char actualBytes2[1] = { 0x62 };
    paraInfo.value = reinterpret_cast<long>(actualBytes2);

    EXPECT_CALL(*this->up, getParaInfo(tid, sysnum, 1, _, _))
        .Times(1)
        .WillOnce(SetArgReferee<4>(paraInfo));

    doPassCheck = basicRule.check(SM_EVM_BASIC_BASE, regs, tid);
    ASSERT_TRUE(doPassCheck);
}

// test both MatchRe and MatchBytes together
TEST_F(BasicRuleFixture, MultiSpec) {
    const int sysnum = 1;
    YAML::Node ruleNode;
    ruleNode[0]["sysnum"] = sysnum;
    ruleNode[0]["id"] = 1;
    ruleNode[0]["specs"].push_back(
        YAML::Load("{ paraIndex: 1, action: matchRe, value: /root/.* }")
    );
    ruleNode[0]["specs"].push_back(
        YAML::Load("{ paraIndex: 2, action: matchBytes, value: [0x2F, 0x64, 0x65, 0x76, 0x2F] }")
    );  // ['/', 'd', 'e', 'v', '/']

    BasicRule basicRule(this->ctxp, ruleNode, this->up);
    user_regs_struct regs;
    int tid;

    // case 1: matchRe not pass (so matchBytes dosen't matter)
    char *actualStr = const_cast<char *>("/root/hello");
    EXPECT_CALL(*this->up, readStrFrom(tid, (char *)regs.rdi, _, SM_MAX_STRING_SIZE))
        .Times(1)
        .WillOnce(SetArrayArgument<2>(actualStr, actualStr + strlen(actualStr) + 1));

    EXPECT_CALL(*this->up, getParaInfo)
        .Times(0);

    bool doPassCheck = basicRule.check(SM_EVM_BASIC_BASE, regs, tid);
    ASSERT_FALSE(doPassCheck);

    // case 2: matchRe pass while matchBytes not pass
    actualStr = const_cast<char *>("/dev/hello");
    EXPECT_CALL(*this->up, readStrFrom(tid, (char *)regs.rdi, _, SM_MAX_STRING_SIZE))
        .Times(1)
        .WillOnce(SetArrayArgument<2>(actualStr, actualStr + strlen(actualStr) + 1));
    
    util::ParaInfo paraInfo;
    paraInfo.size = 7;
    const unsigned char actualBytes[7] = { 0x2F, 0x64, 0x65, 0x76, 0x2F, 0x68, 0x68 };  // "/dev/hh"
    paraInfo.value = reinterpret_cast<long>(actualBytes);
    EXPECT_CALL(*this->up, getParaInfo(tid, sysnum, 2, _, _))
        .Times(1)
        .WillOnce(SetArgReferee<4>(paraInfo));

    doPassCheck = basicRule.check(SM_EVM_BASIC_BASE, regs, tid);
    ASSERT_FALSE(doPassCheck);

    // case 3: both matchRe and matchBytes pass, so the rule actully passes
    actualStr = const_cast<char *>("/dev/hello");
    EXPECT_CALL(*this->up, readStrFrom(tid, (char *)regs.rdi, _, SM_MAX_STRING_SIZE))
        .Times(1)
        .WillOnce(SetArrayArgument<2>(actualStr, actualStr + strlen(actualStr) + 1));
    
    paraInfo.size = 5;
    const unsigned char actualBytes4[5] = { 0x2F, 0x64, 0x65, 0x76, 0x61 };  // "/deva"
    paraInfo.value = reinterpret_cast<long>(actualBytes4);
    EXPECT_CALL(*this->up, getParaInfo(tid, sysnum, 2, _, _))
        .Times(1)
        .WillOnce(SetArgReferee<4>(paraInfo));

    doPassCheck = basicRule.check(SM_EVM_BASIC_BASE, regs, tid);
    ASSERT_TRUE(doPassCheck);
}

TEST_F(BasicRuleFixture, MultiRule) {
    YAML::Node ruleNode;
    ruleNode[0]["sysnum"] = 1;
    ruleNode[0]["id"] = 1;
    ruleNode[0]["specs"].push_back(
        YAML::Load("{ paraIndex: 3, action: matchRe, value: /root/.* }")
    );

    ruleNode[1]["sysnum"] = 2;
    ruleNode[1]["id"] = 2;
    ruleNode[1]["specs"].push_back(
        YAML::Load("{ paraIndex: 1, action: matchBytes, value: [0x2F, 0x64, 0x65, 0x76, 0x2F] }")
    ); // ['/', 'd', 'e', 'v', '/']

    BasicRule basicRule(this->ctxp, ruleNode, this->up);
    user_regs_struct regs;
    int tid;

    // case 1: check the first rule
    char *actualStr = const_cast<char *>("/root/abc");
    EXPECT_CALL(*this->up, readStrFrom(tid, (char *)regs.rdx, _, SM_MAX_STRING_SIZE))
        .Times(1)
        .WillOnce(SetArrayArgument<2>(actualStr, actualStr + strlen(actualStr) + 1));
    
    EXPECT_CALL(*this->up, getParaInfo)
        .Times(0);

    bool doPassCheck = basicRule.check(SM_EVM_BASIC_BASE, regs, tid);
    ASSERT_FALSE(doPassCheck);

    // case 2: check the second rule
    EXPECT_CALL(*this->up, readStrFrom)
        .Times(0);

    util::ParaInfo paraInfo;
    paraInfo.size = 7;
    const unsigned char actualBytes[7] = { 0x2F, 0x64, 0x65, 0x76, 0x2F, 0x68, 0x68 };  // "/dev/hh"
    paraInfo.value = reinterpret_cast<long>(actualBytes);
    EXPECT_CALL(*this->up, getParaInfo(tid, 2, 1, _, _))
        .Times(1)
        .WillOnce(SetArgReferee<4>(paraInfo));

    doPassCheck = basicRule.check(SM_EVM_BASIC_BASE + 1, regs, tid);
    ASSERT_FALSE(doPassCheck);
}

} // namespace test
} // namespace SAIL