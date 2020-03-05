#pragma once

#include <unistd.h>
#include <cassert>
#include <memory>
#include <map>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/socket.h>

#include <spdlog/spdlog.h>

#include "RuleManager.h"
#include "Utils.h"

namespace SAIL { namespace core {

enum SyscallTimes { NOTYET, ONCE, TWICE };

struct RVThreadInfo {
    SyscallTimes syscallTimes;
    user_regs_struct regs;
    long eventMsg;
    RVThreadInfo() {}
    RVThreadInfo(const user_regs_struct &regs, const long eventMsg)
        : syscallTimes(NOTYET), regs(regs), eventMsg(eventMsg) {}
};

class Daemon
{
private:
    
    const pid_t child;
    const std::shared_ptr<rule::RuleManager> rulemgr;
    const std::shared_ptr<util::Utils> up;
    std::map<int, core::RVThreadInfo> RVThreads;

public:
    Daemon(const pid_t child, const std::shared_ptr<rule::RuleManager> &rulemgr, const std::shared_ptr<util::Utils> &up);
    void setOptions();
    void run();
    void handleEvent(const long eventMsg, const pid_t tid, const user_regs_struct &regs);
    void end();
};

} // namespace core
} // namespace SAIL