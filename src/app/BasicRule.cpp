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
                    // don't need extra check yet
                    pSpecs.emplace_back(paraIndex, action, spec["value"].as<int>());
                }

                // build specs, potentially
                if (!needExtraCheck) {
                    const scmp_datum_t value = spec["value"].as<scmp_datum_t>();
                    specs.push_back((struct scmp_arg_cmp){paraIndex, this->cmpActionMap.at(action), value});
                }
            }
        }
        if (!needExtraCheck) {
            this->rules.emplace_back(sysnum, id, specs);
        }
        else {
            this->rules.emplace_back(sysnum, id, pSpecs);
        }
    }

    spdlog::info("init BasicRule module");
    this->initRules();
}

void BasicRule::initRules() {
    int offset = 0;
    for (Rule rule : this->rules) {
        if (rule.needExtraCheck) {
            seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(SM_EVM_BASIC_BASE + offset), rule.sysnum, 0);
        }
        else {
            switch (rule.specs.size()) {
                case 0:
                    seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(SM_EVM_BASIC_BASE + offset), rule.sysnum, 0);
                    break;
                case 1:
                    seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(SM_EVM_BASIC_BASE + offset), rule.sysnum, 1, 
                        rule.specs[0]);
                    break;
                case 2:
                    seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(SM_EVM_BASIC_BASE + offset), rule.sysnum, 2, 
                        rule.specs[0], rule.specs[1]);
                    break;
                case 3:
                    seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(SM_EVM_BASIC_BASE + offset), rule.sysnum, 3, 
                        rule.specs[0], rule.specs[1], rule.specs[2]);
                    break;
                case 4:
                    seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(SM_EVM_BASIC_BASE + offset), rule.sysnum, 4, 
                        rule.specs[0], rule.specs[1], rule.specs[2], rule.specs[3]);
                    break;
                case 5:
                    seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(SM_EVM_BASIC_BASE + offset), rule.sysnum, 5, 
                        rule.specs[0], rule.specs[1], rule.specs[2], rule.specs[3], rule.specs[4]);
                    break;
                case 6:
                    seccomp_rule_add(*this->ctxp, SCMP_ACT_TRACE(SM_EVM_BASIC_BASE + offset), rule.sysnum, 6, 
                        rule.specs[0], rule.specs[1], rule.specs[2], rule.specs[3], rule.specs[4], rule.specs[5]);
                    break;
            }
        }
        offset++;
    }
}

bool BasicRule::check(const long eventMsg, const user_regs_struct &regs, const int tid) {
    const Rule rule = this->rules[eventMsg - SM_EVM_BASIC_BASE];
    if (!rule.needExtraCheck) {
        // don't need extra check but still trapped in, which means an unwanted syscall
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

        if (pSpec.action == "matchRe") {
            // data configured in rule
            const std::regex pattern(pSpec.strValue);
            
            // data to be checked
            char buf[SM_MAX_STRING_SIZE];
            this->up->readStrFrom(tid, (char *)reg, buf, SM_MAX_STRING_SIZE);
            spdlog::info("matchRe: {}", std::string(buf));

            // check
            if (std::regex_match(std::string(buf), pattern)) {
                goto end;
            }
            // spdlog::info("regular expression mismtach");
        }
        else if (pSpec.action == "matchBytes") {
            // data configured in rule
            std::vector<unsigned char> bytes;
            for (const int byte : pSpec.bytesValue) {
                bytes.push_back((unsigned char)(byte));
            }

            // data to be checked
            char buf[SM_MAX_STRING_SIZE];
            this->up->readStrFrom(tid, (char *)reg, buf, SM_MAX_STRING_SIZE);
            // spdlog::info("matchRe: {}", std::string(buf));

            // check (only support bytes in string)
            const int bufSize = strlen(buf);
            const int bytesSize = bytes.size();
            if (bytesSize > bufSize) {
                spdlog::info("bytes configured in rule is longer, mismatch");
                // return true;
                continue;
            }

            for (int i = 0; i <= bufSize - bytesSize; i++) {
                for (int j = 0; j < bytesSize; j++) {
                    // mismatch here
                    if (buf[i + j] != bytes[j])
                        break;

                    // there isn't any mismatch
                    if (j == bytesSize - 1) {
                        goto end;
                    }
                }
            }
            spdlog::info("bytes configured in rule cannot match any part of buf");
        }
        else if (pSpec.action == "equal" && reg == pSpec.intValue) {
            goto end;
        }
        else if (pSpec.action == "notEqual" && reg != pSpec.intValue) {
            goto end;
        }
        else if (pSpec.action == "greater" && reg > pSpec.intValue) {
            goto end;
        }
        else if (pSpec.action == "notGreater" && reg <= pSpec.intValue) {
            goto end;
        }
        else if (pSpec.action == "less" && reg < pSpec.intValue) {
            goto end;
        }
        else if (pSpec.action == "notLess" && reg >= pSpec.intValue) {
            goto end;
        }
    }
    spdlog::info("basic rule {}: all check pass", rule.id);
    return true;

end:
    spdlog::critical("basic rule {} is broke", rule.id);
    return false;
}

} // namespace rule
} // namespace SAIL