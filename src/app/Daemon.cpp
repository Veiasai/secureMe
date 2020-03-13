#include "Daemon.h"
#include "BasicRule.h"
#include "FileWhitelist.h"
#include "NetworkMonitor.h"

namespace SAIL { namespace core {

Daemon::Daemon(const pid_t child, const std::shared_ptr<rule::RuleManager> &rulemgr, const std::shared_ptr<util::Utils> &up) 
    : child(child), rulemgr(rulemgr), up(up) {}

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

        if (isEvent(status, PTRACE_EVENT_CLONE) || isEvent(status, PTRACE_EVENT_FORK) || isEvent(status, PTRACE_EVENT_VFORK)) {
            spdlog::info("clone caught and continue");
            ptrace(PTRACE_CONT, tid, nullptr, nullptr);
            continue;
        }

        if (this->RVThreads.find(tid) != this->RVThreads.end()) {
            // need to catch return value
            if (this->RVThreads[tid].syscallTimes == NOTYET) {
                this->RVThreads[tid].syscallTimes = ONCE;
                ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
                continue;
            }
            else if (this->RVThreads[tid].syscallTimes == ONCE) {
                this->RVThreads[tid].syscallTimes = TWICE;
                user_regs_struct regs;
                this->up->getRegs(tid, &regs);
                this->RVThreads[tid].regs.rax = regs.rax;  // catch return value

                this->handleEvent(this->RVThreads[tid].eventMsg - SM_RETURN_VALUE_OFFSET, tid, this->RVThreads[tid].regs);
                this->RVThreads.erase(tid);
                ptrace(PTRACE_CONT, tid, nullptr, nullptr);
                continue;
            }
        }

        // assert(hasEvent(status) || isNewThread(status));
        if (hasEvent(status)) {
            // get event message
            long msg;
            ptrace(PTRACE_GETEVENTMSG, tid, nullptr, (long)&msg);
            spdlog::info("get event message: {}", msg);

            user_regs_struct regs;
            this->up->getRegs(tid, &regs);
            // handle return value catch
            if (isEvent(status, PTRACE_EVENT_SECCOMP) && msg >= SM_RETURN_VALUE_OFFSET) {
                // in this condition, the wanted data is stored as return value
                // so we need to continue the child process with PTRACE_SYSCALL twice to get it
                // because the first PTRACE_SYSCALL can only catch the call-regs
                // that is to say, the child process receives signals like EVENT->SIGTRAP->SIGTRAP
                // and after the two PTRACE_SYSCALL, another PTRACE_CONT will take place
                this->RVThreads[tid] = RVThreadInfo(regs, msg);
                ptrace(PTRACE_SYSCALL, tid, nullptr, nullptr);
                continue;
            }

            // handle event
            this->handleEvent(msg, tid, regs);
        }

        ptrace(PTRACE_CONT, tid, nullptr, nullptr);
    }
}

void Daemon::handleEvent(const long eventMsg, const pid_t tid, const user_regs_struct &regs) {
    std::shared_ptr<rule::RuleModule> ruleModule = this->rulemgr->getModule(eventMsg);
    bool doPassCheck = ruleModule->check(eventMsg, regs, tid);

    if (!doPassCheck) {
        this->end();
    }
}

void Daemon::end() {
    kill(this->child, SIGKILL);
}

} // namespace core
} // namespace SAIL