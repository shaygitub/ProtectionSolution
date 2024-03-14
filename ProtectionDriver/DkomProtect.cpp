#include "DkomProtect.h"
// Note: functions like PsGetCurrentThreadId() will work because the execution context matches the thread/process


// Global driver variables / exported kernel symbols received in operation / extra definitions:
typedef BYTE(*HalClearLastBranch)(VOID);
PVOID HalClearLastBranchRecordStackActual = NULL;
extern "C" NTSYSCALLAPI NTSTATUS HalPrivateDispatchTable(VOID);  // Holds private dispatch function pointers, used for SwapContext() hook
extern "C" NTSYSCALLAPI NTSTATUS HalEnumerateEnvironmentVariablesEx(VOID);


BOOL ContextSwitchProtection::IsParentProcessHidden(PEPROCESS ThreadParentProcess) {
	PACTEPROCESS CurrentProcess = NULL;
	LIST_ENTRY* CurrentList = NULL;
	LIST_ENTRY* PreviousList = NULL;
	LIST_ENTRY* NextList = NULL;
	LIST_ENTRY* InitialProcessFlink = &((PACTEPROCESS)PsInitialSystemProcess)->ActiveProcessLinks;

	CurrentProcess = (PACTEPROCESS)PsInitialSystemProcess;
	PreviousList = &CurrentProcess->ActiveProcessLinks;
	CurrentList = PreviousList->Flink;
	CurrentProcess = (PACTEPROCESS)((ULONG64)CurrentList - offsetof(struct _ACTEPROCESS, ActiveProcessLinks));
	NextList = CurrentList->Flink;

	while (CurrentList != NULL && CurrentList != InitialProcessFlink) {
		if ((ULONG64)CurrentProcess == (ULONG64)ThreadParentProcess) {
			return FALSE;  // Parent process was found in list
		}
		PreviousList = CurrentList;
		CurrentList = NextList;
		NextList = CurrentList->Flink;
		CurrentProcess = (PACTEPROCESS)((ULONG64)CurrentList - offsetof(struct _ACTEPROCESS, ActiveProcessLinks));
	}
	return TRUE;
}


BOOL ContextSwitchProtection::IsThreadInProcessThreadList(PETHREAD CheckedThread, PEPROCESS ThreadParentProcess) {
	PLIST_ENTRY InitialThreadEntry = (PLIST_ENTRY)((ULONG64)ThreadParentProcess + offsetof(_ACTKPROCESS, ThreadListHead));
	PLIST_ENTRY CurrentThreadEntry = InitialThreadEntry;
	PETHREAD CurrentThread = NULL;


	// Pass the first thread so the while() stop condition (pointer = list head) will not stop function:
	CurrentThread = (PETHREAD)((ULONG64)CurrentThreadEntry - LISTENTRY_ETHREAD_OFFSET);
	if ((ULONG64)CurrentThread == (ULONG64)CheckedThread) {
		return FALSE;  // Thread exists in process thread list
	}
	CurrentThreadEntry = CurrentThreadEntry->Flink;


	// Pass through the whole thread list of the host process to find checked thread:
	while (CurrentThreadEntry != NULL && (ULONG64)CurrentThreadEntry != (ULONG64)InitialThreadEntry) {
		CurrentThread = (PETHREAD)((ULONG64)CurrentThreadEntry - LISTENTRY_ETHREAD_OFFSET);
		if ((ULONG64)CurrentThread == (ULONG64)CheckedThread) {
			return FALSE;  // Thread exists in process thread list
		}
		CurrentThreadEntry = CurrentThreadEntry->Flink;
	}
	return TRUE;  // Thread was unlinked from its EPROCESS's thread list
}


HiddenThreadResults ContextSwitchProtection::IsThreadHidden(PETHREAD CurrentThread) {
	PETHREAD LookupThread = NULL;  // Also check if thread cannot be looked up, if so - might be hidden
	PEPROCESS ThreadParentProcess = (PEPROCESS)((ULONG64)CurrentThread + ETHRD_TO_EPRCS_OFFSET);
	if (CurrentThread == NULL) {
		return InvalidThreadPointer;  // Cannot see if thread is hidden, return FALSE to not stop an unhidden thread
	}
	if (NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)PsGetThreadId(CurrentThread), &LookupThread))) {
		if ((ULONG64)LookupThread == (ULONG64)CurrentThread) {
			return LookupFailed;  // Looked up thread matches the provided thread, cannot be hidden
		}
	}
	if (!ContextSwitchProtection::IsThreadInProcessThreadList(CurrentThread, ThreadParentProcess)) {
		return UnlinkedFromProcessList;
	}
	if (!ContextSwitchProtection::IsParentProcessHidden(ThreadParentProcess)) {
		return ParentProcessHidden;
	}
	return ThreadAndProcessNotHidden;
}


BYTE __fastcall ContextSwitchProtection::EvilHalClearLastBranchRecordStack(VOID) {
	// Note: InstallSwapContextHook is called first so HalClearLastBranchOgFunc will definetally be valid
	HalClearLastBranch HalClearLastBranchOgFunc = (HalClearLastBranch)HalClearLastBranchRecordStackActual;
	PETHREAD CurrentRunningThread = (PETHREAD)__readgsqword(0x188);  // gs::0x188, read 8 bytes to get PETHREAD
	ULONG64 CR3Register = __readcr3();
	UNREFERENCED_PARAMETER(CR3Register);


	// Check for ETHREAD that is not connected to any EPROCESS:
	switch (ContextSwitchProtection::IsThreadHidden(CurrentRunningThread)) {
	case InvalidThreadPointer:
		DbgPrintEx(0, 0, "ProtectionDriver EvilSwapContext() - Cannot find current thread pointer in gs::0x188\n"); return 0;
	case LookupFailed:
		DbgPrintEx(0, 0, "ProtectionDriver EvilSwapContext() - PsLookupThreadByThreadId(%p) failed\n", CurrentRunningThread); return 0;
	case UnlinkedFromProcessList:
		DbgPrintEx(0, 0, "ProtectionDriver EvilSwapContext() - Thread %p was unlinked from parent process thread list\n", CurrentRunningThread); return 0;
	case ParentProcessHidden:
		DbgPrintEx(0, 0, "ProtectionDriver EvilSwapContext() - Thread %p parent process was hidden from process list (probably by DKOM)\n", CurrentRunningThread); return 0;
	case ThreadAndProcessNotHidden:
		break;  // DbgPrintEx(0, 0, "ProtectionDriver EvilSwapContext() - Thread %p and parent process were not hidden\n", CurrentRunningThread); break;
	}
	// TODO: FIND OUT HOW TO STOP CONTEXT SWITCH BY RETURNING DIFFERENT STATUS
	return HalClearLastBranchOgFunc();
}

NTSTATUS ContextSwitchProtection::InstallSwapContextHook() {

    // Hook SwapContext() to monitor running threads (HalPrivateDispatchTable is exported):
	HalClearLastBranchRecordStackActual = *(PVOID*)((ULONG64)HalPrivateDispatchTable + SWAPCTX_HALOFFSET);
    *(PVOID*)((ULONG64)HalPrivateDispatchTable + SWAPCTX_HALOFFSET) = (PVOID)ContextSwitchProtection::EvilHalClearLastBranchRecordStack;
	return STATUS_SUCCESS;  // Open for algorithmic expansion
}


NTSTATUS ContextSwitchProtection::UninstallSwapContextHook() {
	if (HalClearLastBranchRecordStackActual != NULL) {
		*(PVOID*)((ULONG64)HalPrivateDispatchTable + SWAPCTX_HALOFFSET) = HalClearLastBranchRecordStackActual;
	}
	return STATUS_SUCCESS;  // Open for algorithmic expansion
}