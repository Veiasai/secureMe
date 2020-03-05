#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "mock.h"

namespace SAIL { namespace test {

class FileWhitelistFixture : public ::testing::Test {
public:
    // std::vector<std::regex> regFiles;
    std::shared_ptr<scmp_filter_ctx> ctxp;
    std::shared_ptr<MockUtils> up;

    FileWhitelistFixture() {
        this->ctxp.reset(new scmp_filter_ctx(seccomp_init(SCMP_ACT_ALLOW)));
        this->up = std::make_shared<MockUtils>();
    }

    void SetUp() {}

    void TearDown() {}
};

TEST_F(FileWhitelistFixture, InWhitelist) {
    const YAML::Node ruleNode = YAML::Load("[a.txt, b.txt]");
    FileWhitelist fileWhitelist(this->ctxp, ruleNode, this->up);

    user_regs_struct regs;
    int tid;

    const char *filename = "a.txt";
    char c = '1';
    EXPECT_CALL(*this->up, readStrFrom(tid, _, _, SM_MAX_FILENAME))
        .Times(1)
        .WillOnce(SetArrayArgument<2>(filename, filename + strlen(filename) + 1));

    bool doPassCheck = fileWhitelist.check(SM_EVM_OPEN, regs, tid);
    ASSERT_TRUE(doPassCheck);
}
}}