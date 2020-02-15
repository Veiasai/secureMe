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
    for (auto filenameRe : this->ruleNode) {
        const std::string filename = this->handleEscape(filenameRe.as<std::string>());
        seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(SM_EVM_OPEN), SCMP_SYS(open), 0);
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

bool FileWhitelist::checkFile(const std::string &filename) {
    for (std::regex regFile : this->regFiles) {
        if (std::regex_match(filename, regFile)) {
            return true;
        }
    }
    spdlog::critical("open file {}, which is not in whitelist", filename);
    return false;
}

} // namespace rule
} // namespace SAIL