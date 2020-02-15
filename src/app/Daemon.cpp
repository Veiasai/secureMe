#include <sys/user.h>
#include <sys/socket.h>

#include "Daemon.h"
#include "BasicRule.h"
#include "FileWhitelist.h"
#include "NetworkMonitor.h"

namespace SAIL { namespace core {

Daemon::Daemon(const pid_t child, const std::shared_ptr<rule::RuleManager> &rulemgr, const std::shared_ptr<util::Utils> &up) 
    : child(child), rulemgr(rulemgr), up(up) 
{
    int status;
    // catch the execv-caused SIGTRAP here
    waitpid(this->child, &status, WSTOPPED);
    assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
    const long ptraceOptions = PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACESECCOMP;
    ptrace(PTRACE_SETOPTIONS, this->child, nullptr, ptraceOptions);
    ptrace(PTRACE_CONT, this->child, nullptr, nullptr);
}

static bool isEvent(int status, int event)
{
    return (status >> 8) == (SIGTRAP | event << 8);
}

static bool hasEvent(int status)
{
    return status >> 16 != 0;
}

static bool isNewThread(int status)
{
    // new thread will start from stopped state cause by SIGSTOP
    return (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
}

void Daemon::run() {
    int status;
    while (true) {
        int tid = waitpid(-1, &status, 0);
        spdlog::info("----------------------------------------");
        spdlog::info("target {} traps with status: {:x}", tid, status);

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            spdlog::info("target exit");
            break;
        }

        // assert(hasEvent(status) || isNewThread(status));
        if (hasEvent(status)) {
            // get event message
            long msg;
            ptrace(PTRACE_GETEVENTMSG, tid, nullptr, (long)&msg);
            spdlog::info("get event message: {}", msg);

            // handle event
            this->handleEvent(msg, tid);
        }

        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
    }
}

void Daemon::handleEvent(const long eventMsg, const pid_t tid) {
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, tid, nullptr, &regs);

    bool doPassCheck;
    if (SM_IN_BASIC_RULE(eventMsg)) {
        doPassCheck = std::dynamic_pointer_cast<rule::BasicRule>(this->rulemgr->getModule(SM_BASIC_RULE))->check(eventMsg, regs, tid);
    }
    else if (SM_IN_FILE_WHITELIST(eventMsg)) {
        doPassCheck = std::dynamic_pointer_cast<rule::FileWhitelist>(this->rulemgr->getModule(SM_FILE_WHITELIST))->check(eventMsg, regs, tid);
    }
    else if (SM_IN_NETWORK_MONITOR(eventMsg)) {
        doPassCheck = std::dynamic_pointer_cast<rule::NetworkMonitor>(this->rulemgr->getModule(SM_NETWORK_MONITOR))->check(eventMsg, regs, tid);
    }
    else {
        assert(0);
    }

    if (!doPassCheck) {
        this->end();
    }
}

void Daemon::end() {
    kill(this->child, SIGKILL);
}

}}