#pragma once
#include "definitions.h"
#define MOVJMPREG_ADDROFFS 2
#define MOVJMP_ADDROFFS 2
#define PUSHMOVXCHGRETREG_ADDROFFS 3
#define PUSHMOVXCHGRET_ADDROFFS 4

BYTE NtQueryFileHard[28] = { 0 };
BYTE NtQueryFileExHard[35] = { 0 };
BYTE NtQuerySysInfoHard[31] = { 0 };
BYTE NtCreateFileHard[36] = { 0 };
SYSCALL_PROTECT NtQueryDirFileProt;
SYSCALL_PROTECT NtQueryDirFileExProt;
SYSCALL_PROTECT NtCreateFileProt;
SYSCALL_PROTECT NtQuerySysInfoProt;


const BYTE MovJmpPattern[] = "\x48\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\x00";
const BYTE MovJmpRnPattern[] = "\x49\x00\x00\x00\x00\x00\x00\x00\x00\x00\x41\xFF\x00";
const BYTE PushMovXchgRetPattern[] = "\x00\x48\x00\x00\x00\x00\x00\x00\x00\x00\x00\x48\x87\x00\x24\xC3";
const BYTE PushMovXchgRetRnPattern[] = "\x41\x00\x49\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4C\x87\x00\x24\xC3";
const char* MovJmpMask = "x?????????x?";
const char* MovJmpRnMask = "x?????????xx?";
const char* PushMovXchgRetMask = "?x?????????xx?xx";
const char* PushMovXchgRetRnMask = "x?x?????????xx?xx";