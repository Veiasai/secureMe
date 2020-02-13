#include "Daemon.h"

namespace SAIL { namespace core {

Daemon::Daemon(const pid_t child) : child(child) {}

void Daemon::run() {
    int status;
    // catch the execv-caused SIGTRAP here
    waitpid(child, &status, WSTOPPED);
    assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
    ptrace(PTRACE_SETOPTIONS, child, nullptr, PTRACE_O_TRACESECCOMP);
    ptrace(PTRACE_CONT, child, nullptr, nullptr);

    while (true) {
        waitpid(child, &status, 0);
        spdlog::info("target return with status: {:x}", status);
        if (WIFEXITED(status)) {
            spdlog::info("target exit");
            break;
        }
        ptrace(PTRACE_CONT, child, nullptr, nullptr);
    }
}

}}