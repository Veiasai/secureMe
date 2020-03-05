#include "Utils.h"

#include <spdlog/spdlog.h>

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

int Utils::getRegs(int tid, user_regs_struct *regs) {
    return ptrace(PTRACE_GETREGS, tid, nullptr, regs);
}

int Utils::getParaInfo(int tid, const int sysnum, const int paraIndex, const user_regs_struct &regs, ParaInfo &paraInfo) {
    paraInfo = paraInfoTable[sysnum][paraIndex];
    switch (paraInfo.type) {
        case ParaType::lvalue: {
            paraInfo.value = this->paraReg(regs, paraIndex);
            break;
        }
        case ParaType::pointer: {
            paraInfo.size = this->paraReg(regs, paraInfo.size);  // todo: handle return value
            char *buf = new char[paraInfo.size];
            this->readBytesFrom(tid, reinterpret_cast<const char *>(this->paraReg(regs, paraIndex)), buf, paraInfo.size);
            paraInfo.value = reinterpret_cast<long>(buf);
            break;
        }
        case ParaType::str: {
            char *buf = new char[paraInfo.size];
            this->readStrFrom(tid, reinterpret_cast<const char *>(this->paraReg(regs, paraIndex)), buf, paraInfo.size);
            paraInfo.value = reinterpret_cast<long>(buf);
            break;
        }
        case ParaType::structp: {
            char *buf = new char[paraInfo.size];
            this->readBytesFrom(tid, reinterpret_cast<const char *>(this->paraReg(regs, paraIndex)), buf, paraInfo.size);
            paraInfo.value = reinterpret_cast<long>(buf);
            break;
        }
        case ParaType::pArray: {}  // todo
    }
    return 0;
}

bool Utils::needReturnValue(const int sysnum, const int paraIndex, const std::string &action) {
    if (action != "matchBytes") {
        return false;
    }
    const ParaInfo paraInfo = paraInfoTable[sysnum][paraIndex];
    if (paraInfo.size == ParaIndex::Ret) {
        return true;
    }
    return false;
}

long Utils::paraReg(const user_regs_struct &regs, const int index) {
    switch (index) {
        case ParaIndex::Ret:
            return regs.rax;
        case ParaIndex::First:
            return regs.rdi;
        case ParaIndex::Second:
            return regs.rsi;
        case ParaIndex::Third:
            return regs.rdx;
        case ParaIndex::Fourth:
            return regs.rcx;
        case ParaIndex::Fifth:
            return regs.r8;
        case ParaIndex::Sixth:
            return regs.r9;
        default:
            break;
    }
}

} // namespace util
} // namespace SAIL