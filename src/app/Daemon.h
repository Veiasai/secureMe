#pragma once

#include <unistd.h>
#include <cassert>
#include <memory>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#include <spdlog/spdlog.h>

#include "RuleManager.h"
#include "Utils.h"

namespace SAIL { namespace core {

class Daemon
{
private:
    const pid_t child;
    const std::shared_ptr<rule::RuleManager> rulemgr;
    const std::shared_ptr<util::Utils> up;

public:
    Daemon(const pid_t child, const std::shared_ptr<rule::RuleManager> &rulemgr, const std::shared_ptr<util::Utils> &up);
    void run();
    void handleEvent(const long eventMsg, const pid_t tid);
    void end();
};

}}