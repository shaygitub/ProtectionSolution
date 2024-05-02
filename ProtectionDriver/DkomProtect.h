#pragma once
#include "definitions.h"


typedef struct _PROCESS_INFO {
	char ProcessName[15] = { 0 };
	PVOID ProcessId = NULL;
	PVOID OwnerProcessId = NULL;
	UINT Flags3 = 0;
	UINT Flags2 = 0;
	UINT Flags = 0;
	LARGE_INTEGER CreateTime = { 0 };
	EX_FAST_REF Token = { 0 };
	UINT64 Cookie = 0;
	UINT ImagePathHash = 0;
} PROCESS_INFO, *PPROCESS_INFO;


enum HiddenThreadResults {
	InvalidThreadPointer = 0xB00B,
	LookupFailed = 0xC00C,
	UnlinkedFromProcessList = 0xD00D,
	ParentProcessHidden = 0xE00E,
	ThreadAndProcessNotHidden = 0xF00F,
};


namespace HiddenProcessesProtection {
	namespace ProcessList {
		NTSTATUS AddToList(PVOID* List, ULONG64* ListSize, PACTEPROCESS AddProcess);
		BOOL IsInList(PVOID List, ULONG64 ListSize, PPROCESS_INFO Process);
		void FreeList();
		void PrintProcessInfo(PPROCESS_INFO Process);
	}
	NTSTATUS UpdateProcessList();
	void AttachHiddenProcess(PACTEPROCESS HiddenProcess);
	NTSTATUS HiddenProcessProtection(THREAD_STATUS* HiddenProcsThreadStop);
}


/*
namespace ContextSwitchProtection {
	BOOL IsParentProcessHidden(PEPROCESS ThreadParentProcess);
	BOOL IsThreadInProcessThreadList(PETHREAD CheckedThread, PEPROCESS ThreadParentProcess);
	HiddenThreadResults IsThreadHidden(PETHREAD CurrentThread);
	BYTE __fastcall EvilHalClearLastBranchRecordStack(VOID);
	NTSTATUS InstallSwapContextHook();
	NTSTATUS UninstallSwapContextHook();
}
*/