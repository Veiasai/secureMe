#include "FileWhitelist.h"
#include <fcntl.h>                                            

namespace SAIL { namespace rule {

FileWhitelist::FileWhitelist(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode, const std::shared_ptr<util::Utils> &up) : 
    RuleModule(ctxp, ruleNode, up) 
{
    for (const auto &rule : ruleNode.as<std::vector<std::string>>()) {
        this->regFiles.emplace_back(rule);
    }
 
    spdlog::info("init FileWhitelist module");
    this->initRules();
}

void FileWhitelist::initRules(){
    seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(SM_EVM_OPEN), SCMP_SYS(open), 0);
}

bool FileWhitelist::check(const long eventMsg, const user_regs_struct &regs, const int tid) {
    if (eventMsg == SM_EVM_OPEN) {
        // open-caused trap
        char filename[SM_MAX_FILENAME];
        this->up->readStrFrom(tid, (char *)regs.rdi, filename, SM_MAX_FILENAME);
        spdlog::info("open's filename: {}", filename);

        for (std::regex regFile : this->regFiles) {
            if (std::regex_match(filename, regFile)) {
                return true;
            }
        }
        spdlog::critical("open file {}, which is not in whitelist", filename);
        return false;
    }
    // todo: openat
}


} // namespace rule
} // namespace SAIL