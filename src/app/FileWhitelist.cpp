#include "FileWhitelist.h"
#include <fcntl.h>                                            

namespace SAIL { namespace rule {

FileWhitelist::FileWhitelist(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode) : RuleModule(ctxp, ruleNode) {}

void FileWhitelist::initRules(){
    for (auto filenameRe : this->ruleNode) {
        const std::string filename = this->handleEscape(filenameRe.as<std::string>());
        // the parameter of SCMP_ACT_TRACE (1) means open-caused trap
        seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(1), SCMP_SYS(open), 0);
    }
}

std::string FileWhitelist::handleEscape(std::string regStr) {
    for (std::string::iterator it = regStr.begin(); it != regStr.end(); it++) {
        if (*it == '\\') {
            // when encounter a '\\', drop it and preserve the right char after it 
            regStr.erase(it);
        }
    }
    return regStr;
}

} // namespace rule
} // namespace SAIL