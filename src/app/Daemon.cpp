#include "Daemon.h"
#include "BasicRule.h"
#include "FileWhitelist.h"
#include "NetworkMonitor.h"

namespace SAIL { namespace core {

Daemon::Daemon(const pid_t child, const std::shared_ptr<rule::RuleManager> &rulemgr, const std::shared_ptr<util::Utils> &up) 
    : child(child), rulemgr(rulemgr), up(up) {}



void Daemon::setOptions() {
    int status;
    // catch the execv-caused SIGTRAP here
    waitpid(this->child, &status, WSTOPPED);
    assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
    const long ptraceOptions = PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACESECCOMP;
    ptrace(PTRACE_SETOPTIONS, this->child, nullptr, ptraceOptions);
    ptrace(PTRACE_CONT, this->child, nullptr, nullptr);
}

void Daemon::run() {
    int status;
    while (true) {
        int tid = waitpid(-1, &status, 0);
        spdlog::info("----------------------------------------");
        spdlog::info("target {} traps with status: {:x}", tid, status);

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            spdlog::info("target exit");
            break;  // fix: exit of child process of target shouldn't cause termination of target
        }

        this->loop(tid, status);
    }
}

void Daemon::loop(const int tid, const int status) {
    if (this->up->isEvent(status, PTRACE_EVENT_CLONE) || 
        this->up->isEvent(status, PTRACE_EVENT_FORK) || 
        this->up->isEvent(status, PTRACE_EVENT_VFORK)) 
    {
        spdlog::info("clone caught and continue");
        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
        return;
    }

    if (this->RVThreads.find(tid) != this->RVThreads.end()) {
        // need to catch return value
        if (this->RVThreads[tid].syscallTimes == NOTYET) {
            this->RVThreads[tid].syscallTimes = ONCE;
            ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
            return;
        }
        else if (this->RVThreads[tid].syscallTimes == ONCE) {
            this->RVThreads[tid].syscallTimes = TWICE;
            user_regs_struct regs;
            this->up->getRegs(tid, &regs);
            this->RVThreads[tid].regs.rax = regs.rax;  // catch return value

            int r = this->rulemgr->handleEvent(this->RVThreads[tid].eventMsg - SM_RETURN_VALUE_OFFSET, tid, this->RVThreads[tid].regs);
            if (r == 1) {
                this->end();
            }
            this->RVThreads.erase(tid);
            ptrace(PTRACE_CONT, tid, nullptr, nullptr);
            return;
        }
    }

    // assert(hasEvent(status) || isNewThread(status));
    if (this->up->hasEvent(status)) {
        // get event message
        const long msg = this->up->getEventMsg(tid);
        spdlog::info("get event message: {}", msg);

        user_regs_struct regs;
        this->up->getRegs(tid, &regs);
        // handle return value catch
        if (this->up->isEvent(status, PTRACE_EVENT_SECCOMP) && msg >= SM_RETURN_VALUE_OFFSET) {
            // in this condition, the wanted data is stored as return value
            // so we need to continue the child process with PTRACE_SYSCALL twice to get it
            // because the first PTRACE_SYSCALL can only catch the call-regs
            // that is to say, the child process receives signals like EVENT->SIGTRAP->SIGTRAP
            // and after the two PTRACE_SYSCALL, another PTRACE_CONT will take place
            this->RVThreads[tid] = RVThreadInfo(regs, msg);
            ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
            return;
        }

        // handle event
        int r = this->rulemgr->handleEvent(msg, tid, regs);
        if (r == 1) {
            this->end();
        }
    }

    ptrace(PTRACE_CONT, tid, nullptr, nullptr);
}

void Daemon::end() {
    this->up->killTarget(this->child);
}

} // namespace core
} // namespace SAIL