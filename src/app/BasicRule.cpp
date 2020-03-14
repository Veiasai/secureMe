#include "BasicRule.h"

namespace SAIL { namespace rule {

BasicRule::BasicRule(std::shared_ptr<scmp_filter_ctx> ctxp, const YAML::Node &ruleNode, const std::shared_ptr<util::Utils> &up) : 
    RuleModule(ctxp, ruleNode, up) 
{
    for (const auto &rule : ruleNode) {
        const int sysnum = rule["sysnum"].as<int>();
        const int id = rule["id"].as<int>();
        std::vector<struct scmp_arg_cmp> specs;
        std::vector<struct ptrace_arg_cmp> pSpecs;
        bool needExtraCheck = false;
        if (rule["specs"].IsDefined()) {
            for (auto spec : rule["specs"]) {
                const unsigned int paraIndex = spec["paraIndex"].as<unsigned int>();
                const std::string action = spec["action"].as<std::string>();
                
                // build pSpecs
                if (action == "matchRe") {
                    needExtraCheck = true;
                    pSpecs.emplace_back(paraIndex, action, spec["value"].as<std::string>());
                }
                else if (action == "matchBytes") {
                    needExtraCheck = true;
                    pSpecs.emplace_back(paraIndex, action, spec["value"].as<std::vector<int>>());
                }
                else {
                    // don't need extra check
                    const scmp_datum_t value = spec["value"].as<scmp_datum_t>();
                    specs.push_back((struct scmp_arg_cmp){paraIndex, this->cmpActionMap.at(action), value});
                }
            }
        }
        if (!needExtraCheck) {
            this->rules.emplace_back(sysnum, id, specs);
        }
        else {
            this->rules.emplace_back(sysnum, id, specs, pSpecs);
        }
    }

    spdlog::info("init BasicRule module");
    this->initRules();
}

void BasicRule::initRules() {
    int offset = 0;
    for (Rule rule : this->rules) {
        int returnValueOffset = 0;
        for (struct ptrace_arg_cmp pSpec : rule.pSpecs) {
            if (this->up->needReturnValue(rule.sysnum, pSpec.paraIndex, pSpec.action)) {
                returnValueOffset = SM_RETURN_VALUE_OFFSET;
                break;
            }
        }
        
        // to be consistent with ToBeCarried, once one of the specs is hit, the whole rule is considered as broken
        // seccomp's logic is that only all specs are hit would the rule be considered as broken so we need a little trick
        if (rule.specs.empty()) {
            seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(SM_EVM_BASIC_BASE + offset + returnValueOffset), rule.sysnum, 0);
        }
        for (auto spec : rule.specs) {
            seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(SM_EVM_BASIC_BASE + offset + returnValueOffset), rule.sysnum, 1, spec);
        }
        offset++;
    }
}

bool BasicRule::check(const long eventMsg, const user_regs_struct &regs, const int tid) {
    const Rule rule = this->rules[eventMsg - SM_EVM_BASIC_BASE];
    if (!rule.needExtraCheck || !rule.specs.empty()) {
        // don't need extra check or there are some para checks that seccomp could handle
        // but still trapped in, which means an unwanted syscall
        // that is to say, the check method only serves matchRe and matchBytes
        goto end;
    }

    // start extra check
    for (const auto &pSpec : rule.pSpecs) {
        unsigned long long reg;
        switch (pSpec.paraIndex) {
            case 1:
                reg = regs.rdi;
                break;
            case 2:
                reg = regs.rsi;
                break;
            case 3:
                reg = regs.rdx;
                break;
            case 4:
                reg = regs.rcx;
                break;
            case 5:
                reg = regs.r8;
                break;
            case 6:
                reg = regs.r9;
                break;
        }

        if (pSpec.action == "matchRe" && !this->matchRe(pSpec, reg, tid)) {
            goto end;
        }
        else if (pSpec.action == "matchBytes" && !this->matchBytes(pSpec, regs, tid, rule.sysnum)) {
            goto end;
        }
    }
    spdlog::info("basic rule {}: all check pass", rule.id);
    return true;

end:
    spdlog::critical("basic rule {} is broke", rule.id);
    return false;
}

bool BasicRule::matchRe(const struct ptrace_arg_cmp &pSpec, const unsigned long long reg, const int tid) {
    // data configured in rule
    const std::regex pattern(pSpec.strValue);
    
    // data to be checked
    char buf[SM_MAX_STRING_SIZE];
    this->up->readStrFrom(tid, (char *)reg, buf, SM_MAX_STRING_SIZE);
    spdlog::info("matchRe: {}", std::string(buf));

    // check
    if (std::regex_match(std::string(buf), pattern)) {
        return false;
    }
    spdlog::info("regular expression mismtach");
    return true;
}

bool BasicRule::matchBytes(const struct ptrace_arg_cmp &pSpec, const user_regs_struct &regs, const int tid, const int sysnum) {
    // data configured in rule
    std::vector<unsigned char> bytes;
    for (const int byte : pSpec.bytesValue) {
        bytes.push_back((unsigned char)(byte));
    }

    // data to be checked
    util::ParaInfo paraInfo;
    this->up->getParaInfo(tid, sysnum, pSpec.paraIndex, regs, paraInfo);
    const unsigned char *actualBytes = reinterpret_cast<const unsigned char *>(paraInfo.value);
    const long actualSize = paraInfo.size;

    // check
    const int bytesSize = bytes.size();
    if (bytesSize > actualSize) {
        spdlog::info("bytes configured in rule is longer, mismatch");
        return true;
    }

    for (int i = 0; i <= actualSize - bytesSize; i++) {
        for (int j = 0; j < bytesSize; j++) {
            // mismatch here
            if (actualBytes[i + j] != bytes[j])
                break;

            // there isn't any mismatch
            if (j == bytesSize - 1) {
                return false;
            }
        }
    }
    spdlog::info("bytes configured in rule cannot match any part of buf");
    return true;
}

} // namespace rule
} // namespace SAIL