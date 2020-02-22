#pragma once

#include <stdlib.h>
#include <sys/user.h>
#include <sys/ptrace.h>

namespace SAIL { namespace util {

class Utils
{
public:
    virtual int readStrFrom(int tid, const char *p, char *buf, size_t s);
    virtual int readBytesFrom(int tid, const char *p, char *buf, size_t s);
    virtual int getRegs(int tid, user_regs_struct &regs);
};

} // namespace util
} // namespace SAIL