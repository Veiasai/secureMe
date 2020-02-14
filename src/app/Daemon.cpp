#include "Daemon.h"
#include <sys/user.h>
namespace SAIL { namespace core {

Daemon::Daemon(const pid_t child, const std::shared_ptr<rule::RuleManager> &rulemgr, const std::shared_ptr<util::Utils> &up) 
    : child(child), rulemgr(rulemgr), up(up) 
{
    int status;
    // catch the execv-caused SIGTRAP here
    waitpid(this->child, &status, WSTOPPED);
    assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
    ptrace(PTRACE_SETOPTIONS, this->child, nullptr, PTRACE_O_TRACESECCOMP);
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

void Daemon::run() {
    int status;
    while (true) {
        waitpid(this->child, &status, 0);
        spdlog::info("target return with status: {:x}", status);
        
        if (WIFEXITED(status)) {
            spdlog::info("target exit");
            break;
        }

        // get event message
        assert(hasEvent(status));
        long msg;
        ptrace(PTRACE_GETEVENTMSG, this->child, nullptr, (long)&msg);
        spdlog::info("get event message: {}", msg);

        // handle event
        this->handleEvent(msg);

        ptrace(PTRACE_CONT, this->child, nullptr, nullptr);
    }
}

void Daemon::handleEvent(const long eventMsg) {
    if (eventMsg == 1) {
        // open-caused trap
        user_regs_struct regs;
        ptrace(PTRACE_GETREGS, this->child, nullptr, &regs);
        // spdlog::info("open's first arg: {}", regs.rdi);
        char buf[1000];
        this->up->readStrFrom(this->child, (char *)regs.rdi, buf, 1000);
        spdlog::info("open's filename: {}", buf);
    }
}

}}