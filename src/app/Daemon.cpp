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
        bool inWhitelist = std::dynamic_pointer_cast<rule::FileWhitelist>(this->rulemgr->getModule("FileWhitelist"))->checkFile(buf);
        spdlog::info("inWhitelist: {}", inWhitelist);
    }
    else if (eventMsg == 2) {
        // connect-caused trap
        user_regs_struct regs;
        ptrace(PTRACE_GETREGS, this->child, nullptr, &regs);
        const int size = regs.rdx;
        spdlog::info("sockaddr length: {}", size);
        char *buf = new char(size);
        this->up->readBytesFrom(this->child, (char *)regs.rsi, buf, size);
        const struct sockaddr *sa = reinterpret_cast<struct sockaddr *>(buf);
        if (sa->sa_family == AF_INET)
        {
            const struct sockaddr_in *sa_in = reinterpret_cast<const struct sockaddr_in *>(sa);
            const in_addr_t ipv4 = sa_in->sin_addr.s_addr;
            spdlog::debug("NetworkMonitor: catch connect {}", ipv4);
            bool inWhitelist = std::dynamic_pointer_cast<rule::NetworkMonitor>(this->rulemgr->getModule("NetworkMonitor"))->checkIPv4(ipv4);
            spdlog::info("inWhitelist: {}", inWhitelist);
        }
    }
}

}}