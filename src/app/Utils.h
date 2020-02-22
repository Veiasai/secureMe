#pragma once

#include <stdlib.h>
#include <sys/ptrace.h>

namespace SAIL { namespace util {

class Utils
{
public:
    virtual int readStrFrom(int tid, const char *p, char *buf, size_t s);
    virtual int readBytesFrom(int tid, const char *p, char *buf, size_t s);
};

} // namespace util
} // namespace SAIL