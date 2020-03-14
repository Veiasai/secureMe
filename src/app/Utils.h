#pragma once

#include <string>
#include <stdlib.h>
#include <sys/user.h>
#include <sys/ptrace.h>

#include "ParaInfo.h"

namespace SAIL { namespace util {

class Utils
{
public:
    virtual int readStrFrom(int tid, const char *p, char *buf, size_t s);
    virtual int readBytesFrom(int tid, const char *p, char *buf, size_t s);
    virtual int getRegs(int tid, user_regs_struct *regs);
    virtual int getParaInfo(int tid, const int sysnum, const int paraIndex, const user_regs_struct &regs, ParaInfo &paraInfo);
    virtual long paraReg(const user_regs_struct &regs, const int index);
    virtual bool needReturnValue(const int sysnum, const int paraIndex, const std::string &action);
    virtual bool isEvent(const int status, const int event);
    virtual bool hasEvent(const int status);
    virtual bool isNewThread(const int status);
    virtual long getEventMsg(const int tid);
    virtual void killTarget(const int tid);
};

} // namespace util
} // namespace SAIL