#pragma once
#include "definitions.h"


enum HiddenThreadResults {
	InvalidThreadPointer = 0xB00B,  // ;)
	LookupFailed = 0xC00C,
	UnlinkedFromProcessList = 0xD00D,
	ParentProcessHidden = 0xE00E,
	ThreadAndProcessNotHidden = 0xF00F,
};


namespace ContextSwitchProtection {
	BOOL IsParentProcessHidden(PEPROCESS ThreadParentProcess);
	BOOL IsThreadInProcessThreadList(PETHREAD CheckedThread, PEPROCESS ThreadParentProcess);
	HiddenThreadResults IsThreadHidden(PETHREAD CurrentThread);
	BYTE __fastcall EvilHalClearLastBranchRecordStack(VOID);
	NTSTATUS InstallSwapContextHook();
	NTSTATUS UninstallSwapContextHook();
}