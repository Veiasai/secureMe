#pragma once

// event message macro
#define SM_EVM_OPEN         10
#define SM_EVM_CONNECT      20
#define SM_EVM_BASIC_BASE   100

// rule module macro
#define SM_IN_FILE_WHITELIST(x)     (((x) >= 10) && ((x) < 20))
#define SM_IN_NETWORK_MONITOR(x)    (((x) >= 20) && ((x) < 30))
#define SM_IN_BASIC_RULE(x)         ((x) >= 100)

// max filename size
#define SM_MAX_FILENAME     256

// max string size
#define SM_MAX_STRING_SIZE  1024