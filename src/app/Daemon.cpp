#include <sys/user.h>
#include <sys/socket.h>

#include "Daemon.h"
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

        if (WIFEXITED(status)) {
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

    if (eventMsg == SM_EVM_OPEN) {
        // open-caused trap
        char buf[SM_MAX_FILENAME];
        this->up->readStrFrom(tid, (char *)regs.rdi, buf, SM_MAX_FILENAME);
        spdlog::info("open's filename: {}", buf);
        bool inWhitelist = std::dynamic_pointer_cast<rule::FileWhitelist>(this->rulemgr->getModule("FileWhitelist"))->checkFile(buf);
        spdlog::info("inWhitelist: {}", inWhitelist);
    }
    else if (eventMsg == SM_EVM_CONNECT) {
        // connect-caused trap
        const int size = regs.rdx;
        spdlog::info("sockaddr length: {}", size);
        char *buf = new char(size);
        this->up->readBytesFrom(tid, (char *)regs.rsi, buf, size);
        const struct sockaddr *sa = reinterpret_cast<struct sockaddr *>(buf);
        if (sa->sa_family == AF_INET) {
            const struct sockaddr_in *sa_in = reinterpret_cast<const struct sockaddr_in *>(sa);
            const in_addr_t ipv4 = sa_in->sin_addr.s_addr;
            spdlog::debug("NetworkMonitor: catch connect {}", ipv4);
            bool inWhitelist = std::dynamic_pointer_cast<rule::NetworkMonitor>(this->rulemgr->getModule("NetworkMonitor"))->checkIPv4(ipv4);
            spdlog::info("inWhitelist: {}", inWhitelist);
        }
    }
}

}}