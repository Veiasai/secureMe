#pragma once

#include <stdlib.h>
#include <sys/ptrace.h>

namespace SAIL { namespace util {

class Utils
{
public:
    int readStrFrom(int tid, const char *p, char *buf, size_t s);
    int readBytesFrom(int tid, const char *p, char *buf, size_t s);
};

} // namespace util
} // namespace SAIL