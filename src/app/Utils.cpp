#include "Utils.h"

namespace SAIL { namespace util {

int Utils::readStrFrom(int tid, const char *p, char *buf, size_t s)
{
    for (int i = 0; i < s; i += sizeof(long)) {
        long val = ptrace(PTRACE_PEEKDATA, tid, (long)p + i, nullptr);
        char *c = (char *)&val;
        for (int j = 0; j < 8; j++) {
            buf[i + j] = c[j];
            if (c[j] == '\0') {
                return 0;
            }
        }
    }
    return -1;
}

int Utils::readBytesFrom(int tid, const char *p, char *buf, size_t s)
{
    size_t count = 0;
    while (s - count > 8) {
        *(long *)(buf + count) = ptrace(PTRACE_PEEKDATA, tid, (long)p + count, nullptr);
        // spdlog::debug("[tid: {}] [readBytesFrom] [{}]", tid, buf+count);
        count += 8;
    }

    if (s - count > 0) {
        long data = ptrace(PTRACE_PEEKDATA, tid, (long)p + count, nullptr);
        char *bdata = (char *)&data;
        // spdlog::debug("[tid: {}] [readBytesFrom] [{}]", tid, bdata);
        for (int i = 0; count + i < s; i++) {
            buf[count + i] = bdata[i];
        }
    }
    return 0;
}

int Utils::getRegs(int tid, user_regs_struct &regs) {
    return ptrace(PTRACE_GETREGS, tid, nullptr, regs);
}

} // namespace util
} // namespace SAIL