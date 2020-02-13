#pragma once

#include <unistd.h>
#include <cassert>
#include <memory>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#include <spdlog/spdlog.h>

namespace SAIL { namespace core {

class Daemon
{
private:
    pid_t child;

public:
    Daemon(const pid_t child);
    void run();
};

}}