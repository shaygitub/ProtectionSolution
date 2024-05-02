#include "DkomProtect.h"
#pragma warning(disable : 4996)
// Note: functions like PsGetCurrentThreadId() will work because the execution context matches the thread/process


// Global driver variables / exported kernel symbols received in operation / extra definitions:
/*
typedef BYTE(*HalClearLastBranch)(VOID);
PVOID HalClearLastBranchRecordStackActual = NULL;
extern "C" NTSYSCALLAPI NTSTATUS HalPrivateDispatchTable(VOID);  // Holds private dispatch function pointers, used for SwapContext() hook
extern "C" NTSYSCALLAPI NTSTATUS HalEnumerateEnvironmentVariablesEx(VOID);
*/
PVOID HiddenProcessesList = NULL;
ULONG64 HiddenProcessesSize = 0;


NTSTATUS HiddenProcessesProtection::ProcessList::AddToList(PVOID* List, ULONG64* ListSize, PACTEPROCESS AddProcess) {
	PROCESS_INFO ProcessInformation = { 0 };
	PVOID TemporaryList = NULL;
	ULONG64 AppendOffset = 0;
	if (List == NULL || ListSize == NULL || AddProcess == NULL || 
		(*List != NULL && *ListSize == 0) || (*List == NULL && *ListSize != 0)) {
		return STATUS_INVALID_PARAMETER;
	}


	// Allocate memory for list:
	if (*List == NULL) {

		// List is empty/nonexistent:
		*List = ExAllocatePoolWithTag(NonPagedPool, sizeof(PROCESS_INFO), 'ChPp');
		if (*List == NULL) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}
	}
	else {

		// List is not empty:
		TemporaryList = ExAllocatePoolWithTag(NonPagedPool, *ListSize + sizeof(PROCESS_INFO), 'ThPp');
		if (TemporaryList == NULL) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}
		RtlCopyMemory(TemporaryList, *List, *ListSize);
		ExFreePool(*List);
		*List = TemporaryList;
		AppendOffset = *ListSize;
	}


	// Resolve new process information and add it to list:
	ProcessInformation.Cookie = AddProcess->Cookie;
	ProcessInformation.CreateTime = AddProcess->CreateTime;
	ProcessInformation.Flags = AddProcess->Flags;
	ProcessInformation.Flags2 = AddProcess->Flags2;
	ProcessInformation.Flags3 = AddProcess->Flags3;
	ProcessInformation.ImagePathHash = AddProcess->ImagePathHash;
	ProcessInformation.OwnerProcessId = (PVOID)AddProcess->OwnerProcessId;
	ProcessInformation.ProcessId = AddProcess->UniqueProcessId;
	RtlCopyMemory(ProcessInformation.ProcessName, AddProcess->ImageFileName, 15);
	ProcessInformation.Token.Object = AddProcess->Token.Object;
	RtlCopyMemory((PVOID)((ULONG64)*List + AppendOffset), &ProcessInformation, sizeof(PROCESS_INFO));
	*ListSize += sizeof(PROCESS_INFO);
	return STATUS_SUCCESS;
}


void HiddenProcessesProtection::ProcessList::PrintProcessInfo(PPROCESS_INFO Process) {
	DbgPrintEx(0, 0, "ProtectionDriver HiddenProcessesProtection() process print:\n");
	DbgPrintEx(0, 0, "%s\n", Process->ProcessName);
	DbgPrintEx(0, 0, "%llu\n", Process->Cookie);
	DbgPrintEx(0, 0, "%llu\n", Process->CreateTime.QuadPart);
	DbgPrintEx(0, 0, "%lu\n", Process->Flags);
	DbgPrintEx(0, 0, "%lu\n", Process->Flags2);
	DbgPrintEx(0, 0, "%lu\n", Process->Flags3);
	DbgPrintEx(0, 0, "%lu\n", Process->ImagePathHash);
	DbgPrintEx(0, 0, "%llu\n", (ULONG64)Process->OwnerProcessId);
	DbgPrintEx(0, 0, "%llu\n", (ULONG64)Process->ProcessId);
	DbgPrintEx(0, 0, "%llu\n", (ULONG64)Process->Token.Object);
}


BOOL HiddenProcessesProtection::ProcessList::IsInList(PVOID List, ULONG64 ListSize, PPROCESS_INFO Process) {
	PROCESS_INFO CurrentProcess = { 0 };
	for (ULONG64 HiddenIndex = 0; HiddenIndex < ListSize; HiddenIndex += sizeof(PROCESS_INFO)) {
		RtlCopyMemory(&CurrentProcess, (PVOID)((ULONG64)List + HiddenIndex), sizeof(PROCESS_INFO));
		if ((ULONG64)CurrentProcess.ProcessId == (ULONG64)Process->ProcessId) {
			return TRUE;
		}
	}
	return FALSE;
}


void HiddenProcessesProtection::ProcessList::FreeList() {
	if (HiddenProcessesList != NULL) {
		ExFreePool(HiddenProcessesList);
		HiddenProcessesList = NULL;
		HiddenProcessesSize = 0;
	}
}


void HiddenProcessesProtection::AttachHiddenProcess(PACTEPROCESS HiddenProcess) {
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
		PreviousList = CurrentList;
		CurrentList = NextList;
		NextList = CurrentList->Flink;
		CurrentProcess = (PACTEPROCESS)((ULONG64)CurrentList - offsetof(struct _ACTEPROCESS, ActiveProcessLinks));
	}
	PreviousList->Flink = &HiddenProcess->ActiveProcessLinks;
	HiddenProcess->ActiveProcessLinks.Blink = PreviousList;
	HiddenProcess->ActiveProcessLinks.Flink = CurrentList;
	DbgPrintEx(0, 0, "ProtectionDriver HiddenProcessesProtection() - Process %p, %llu was reattached to list\n",
		HiddenProcess, (ULONG64)HiddenProcess->UniqueProcessId);
}


NTSTATUS HiddenProcessesProtection::UpdateProcessList() {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PVOID NewProcessList = NULL;
	ULONG64 NewListSize = 0;
	LIST_ENTRY* CurrentList = NULL;
	LIST_ENTRY* PreviousList = NULL;
	LIST_ENTRY* NextList = NULL;
	PACTEPROCESS CurrentProcess = (PACTEPROCESS)PsInitialSystemProcess;
	LIST_ENTRY* LastProcessFlink = &CurrentProcess->ActiveProcessLinks;
	PROCESS_INFO CurrentProcessInList = { 0 };
	PACTEPROCESS ProcessInNewList = NULL;


	// Iterate the current process list to create a new list:
	PreviousList = LastProcessFlink;
	CurrentList = PreviousList->Flink;
	CurrentProcess = (PACTEPROCESS)((ULONG64)CurrentList - offsetof(struct _ACTEPROCESS, ActiveProcessLinks));
	NextList = CurrentList->Flink;
	while (CurrentList != LastProcessFlink) {
		Status = HiddenProcessesProtection::ProcessList::AddToList(&NewProcessList, &NewListSize, 
			CurrentProcess);
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "ProtectionDriver HiddenProcessesProtection() - failed to add process %p: 0x%x\n",
				CurrentProcess, Status);
			return Status;
		}
		//DbgPrintEx(0, 0, "ProtectionDriver HiddenProcessesProtection() - added process %p to list\n",
		//	CurrentProcess);
		PreviousList = CurrentList;
		CurrentList = NextList;
		NextList = CurrentList->Flink;
		CurrentProcess = (PACTEPROCESS)((ULONG64)CurrentList - offsetof(struct _ACTEPROCESS, ActiveProcessLinks));
	}


	// If this list is the first logging session - no hidden process can be traced:
	if (HiddenProcessesList != NULL) {
		for (ULONG64 HiddenIndex = 0; HiddenIndex < HiddenProcessesSize; HiddenIndex += sizeof(PROCESS_INFO)) {
			RtlCopyMemory(&CurrentProcessInList, (PVOID)((ULONG64)HiddenProcessesList +
				HiddenIndex), sizeof(PROCESS_INFO));
			if (HiddenProcessesProtection::ProcessList::IsInList(NewProcessList, NewListSize, &CurrentProcessInList)) {
				continue;  // If process is in both lists - no need to analyze
			}

			// Old process is not in current list, lookup to see if hidden:
			Status = PsLookupProcessByProcessId((HANDLE)CurrentProcessInList.ProcessId,
				(PEPROCESS*)&ProcessInNewList);
			if (!NT_SUCCESS(Status) || ProcessInNewList == NULL) {
				DbgPrintEx(0, 0, "ProtectionDriver HiddenProcessesProtection() - process %llu terminated regularly\n",
					(ULONG64)CurrentProcessInList.ProcessId);
				continue;
			}

			// Lookup of old process in new list succeeded but comparing failed - hidden process:
			DbgPrintEx(0, 0, "ProtectionDriver HiddenProcessesProtection() - process %llu was hidden, reattaching ..\n",
				(ULONG64)ProcessInNewList->UniqueProcessId);
			HiddenProcessesProtection::AttachHiddenProcess(ProcessInNewList);
		}
		ExFreePool(HiddenProcessesList);
		HiddenProcessesList = NULL;
		HiddenProcessesSize = 0;
	}
	HiddenProcessesList = NewProcessList;
	HiddenProcessesSize = NewListSize;
	return STATUS_SUCCESS;
}


NTSTATUS HiddenProcessesProtection::HiddenProcessProtection(THREAD_STATUS* HiddenProcsThreadStop) {
	LARGE_INTEGER TimerNanoCount = { 0 };
	TimerNanoCount.QuadPart = 600000000;  // 600,000,000 units of 100 nano seconds = 60 seconds


	// Make an infinite loop to check for any manipulations:
	while (*HiddenProcsThreadStop != TerminateStatus) {
		HiddenProcessesProtection::UpdateProcessList();

		// Delay this thread's execution to mimic Sleep() for 5 seconds:
		if (!NT_SUCCESS(KeDelayExecutionThread(KernelMode, FALSE, &TimerNanoCount))) {
			DbgPrintEx(0, 0, "ProtectionDriver hidden processes protection - Failed to delay thread execution\n");
		}
	}
	DbgPrintEx(0, 0, "ProtectionDriver - HiddenProcessesProtection() terminated\n");
	*HiddenProcsThreadStop = FinishedStatus;
	return NULL;
}
/*
BOOL ContextSwitchProtection::IsParentProcessHidden(PEPROCESS ThreadParentProcess) {
	PACTEPROCESS CurrentProcess = NULL;
	PACTEPROCESS ParentProcess = (PACTEPROCESS)ThreadParentProcess;
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


	// If parent process is not linked - link it back to list and fail the context switch:
	PreviousList->Flink = &ParentProcess->ActiveProcessLinks;
	ParentProcess->ActiveProcessLinks.Blink = PreviousList;
	ParentProcess->ActiveProcessLinks.Flink = CurrentList;
	DbgPrintEx(0, 0, "ProtectionDriver EvilSwapContext() - Parent EPROCESS %p was not found in the list, reattached\n", ThreadParentProcess);
	return TRUE;
}


BOOL ContextSwitchProtection::IsThreadInProcessThreadList(PETHREAD CheckedThread, PEPROCESS ThreadParentProcess) {
	PLIST_ENTRY InitialThreadEntry = (PLIST_ENTRY)((ULONG64)ThreadParentProcess + offsetof(_ACTKPROCESS, ThreadListHead));
	PLIST_ENTRY CurrentThreadEntry = InitialThreadEntry;
	PLIST_ENTRY PreviousThreadEntry = NULL;
	PLIST_ENTRY CheckedThreadEntry = NULL;
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


	// Thread was unlinked from its EPROCESS's thread list - Attach it back:
	if (CurrentThreadEntry != NULL) {
		PreviousThreadEntry = CurrentThreadEntry->Blink;
		CheckedThreadEntry = (PLIST_ENTRY)((ULONG64)CheckedThread + LISTENTRY_ETHREAD_OFFSET);
		CheckedThreadEntry->Blink = PreviousThreadEntry;
		PreviousThreadEntry->Flink = CheckedThreadEntry;
		CurrentThreadEntry->Blink = CheckedThreadEntry;
		DbgPrintEx(0, 0, "ProtectionDriver EvilSwapContext() - EHTREAD %p of parent EPROCESS %p was not found in the list, reattached\n",
			CheckedThread, ThreadParentProcess);
	}
	return TRUE;
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
		DbgPrintEx(0, 0, "ProtectionDriver EvilSwapContext() - Cannot find current thread pointer in gs::0x188\n"); break;// return 0;
	case LookupFailed:
		DbgPrintEx(0, 0, "ProtectionDriver EvilSwapContext() - PsLookupThreadByThreadId(%p) failed\n", CurrentRunningThread); break;// return 0;
	case UnlinkedFromProcessList:
		DbgPrintEx(0, 0, "ProtectionDriver EvilSwapContext() - Thread %p was unlinked from parent process thread list\n", CurrentRunningThread); break;// return 0;
	case ParentProcessHidden:
		DbgPrintEx(0, 0, "ProtectionDriver EvilSwapContext() - Thread %p parent process was hidden from process list (probably by DKOM)\n", CurrentRunningThread); break;// return 0;
	case ThreadAndProcessNotHidden:
		DbgPrintEx(0, 0, "ProtectionDriver EvilSwapContext() - Thread %p and parent process were not hidden\n", CurrentRunningThread); break;
	}
	return HalClearLastBranchOgFunc();
}

NTSTATUS ContextSwitchProtection::InstallSwapContextHook() {

    // Hook SwapContext() to monitor running threads (HalPrivateDispatchTable is exported):
	HalClearLastBranchRecordStackActual = *(PVOID*)((ULONG64)HalPrivateDispatchTable + SWAPCTX_HALOFFSET);
    *(PVOID*)((ULONG64)HalPrivateDispatchTable + SWAPCTX_HALOFFSET) = (PVOID)ContextSwitchProtection::EvilHalClearLastBranchRecordStack;
	

	// Make sure current value is not the same as the original:
	if (*(PVOID*)((ULONG64)HalPrivateDispatchTable + SWAPCTX_HALOFFSET) == HalClearLastBranchRecordStackActual) {
		DbgPrintEx(0, 0, "ProtectionDriver EvilSwapContext() - HalClearLastBranchRecordStack hook failed\n");
		return STATUS_UNSUCCESSFUL;
	}
	DbgPrintEx(0, 0, "ProtectionDriver EvilSwapContext() - HalClearLastBranchRecordStack hooked successfully\n");
	return STATUS_SUCCESS;  // Open for algorithmic expansion
}


NTSTATUS ContextSwitchProtection::UninstallSwapContextHook() {
	if (HalClearLastBranchRecordStackActual != NULL) {
		*(PVOID*)((ULONG64)HalPrivateDispatchTable + SWAPCTX_HALOFFSET) = HalClearLastBranchRecordStackActual;
		if (*(PVOID*)((ULONG64)HalPrivateDispatchTable + SWAPCTX_HALOFFSET) != HalClearLastBranchRecordStackActual) {
			DbgPrintEx(0, 0, "ProtectionDriver EvilSwapContext() - HalClearLastBranchRecordStack unhook failed\n");
			return STATUS_UNSUCCESSFUL;
		}
	}
	DbgPrintEx(0, 0, "ProtectionDriver EvilSwapContext() - HalClearLastBranchRecordStack unhooked successfully\n");
	return STATUS_SUCCESS;  // Open for algorithmic expansion
}
*/