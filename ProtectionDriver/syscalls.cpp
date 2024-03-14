#include "SyscallsGlobals.h"
#include "syscalls.h"
#include "helpers.h"
#pragma warning(disable : 6387)


NTSTATUS InitializeSyscallProtectedFunction(LPCWSTR FunctionName, ULONG64 FullInstructionSize, PSYSCALL_PROTECT ProtectedData, ULONG SyscallNumber) {

	// Verify that all of the parameters are valid:
	if (ProtectedData == NULL || FunctionName == NULL || FullInstructionSize == 0 || SyscallNumber == 0) {
		return STATUS_INVALID_PARAMETER;
	}

	// Initialize name and get the address of the system service in the kernel exports and the SSDT table:
	RtlInitUnicodeString(&ProtectedData->FunctionName, FunctionName);
	ProtectedData->FunctionAddressKernelExport = MmGetSystemRoutineAddress(&ProtectedData->FunctionName);
	if (ProtectedData->FunctionAddressKernelExport == NULL) {
		return STATUS_ADDRESS_NOT_ASSOCIATED;
	}
	ProtectedData->FunctionDataSSDTEntry = (PVOID)SSDT::CurrentSSDTFuncAddr(SyscallNumber);
	if (ProtectedData->FunctionDataSSDTEntry != ProtectedData->FunctionAddressKernelExport) {
		return STATUS_UNSUCCESSFUL;
	}

	// Fill the original data of the function with NOPs and set the actual used size (determined with windbg):
	for (USHORT DataIndex = 0; DataIndex < MAX_PROTECTED_DATA; DataIndex++) {
		ProtectedData->OriginalData[DataIndex] = 0x90;  // nop
	}


	// Save the pointer to the hardcoded original data of the function:
	if (wcscmp(FunctionName, L"NtQueryInformationFile") == 0) {
		ProtectedData->HardcodedOriginalMemory.MemoryBuffer = NtQueryFileHard;
		ProtectedData->HardcodedOriginalMemory.MemorySize = sizeof(NtQueryFileHard);
	}
	else if (wcscmp(FunctionName, L"NtQueryInformationFileEx") == 0) {
		ProtectedData->HardcodedOriginalMemory.MemoryBuffer = NtQueryFileExHard;
		ProtectedData->HardcodedOriginalMemory.MemorySize = sizeof(NtQueryFileExHard);
	}
	else if (wcscmp(FunctionName, L"NtQuerySystemInformation") == 0) {
		ProtectedData->HardcodedOriginalMemory.MemoryBuffer = NtQuerySysInfoHard;
		ProtectedData->HardcodedOriginalMemory.MemorySize = sizeof(NtQuerySysInfoHard);
	}
	else if (wcscmp(FunctionName, L"NtCreateFile") == 0) {
		ProtectedData->HardcodedOriginalMemory.MemoryBuffer = NtCreateFileHard;
		ProtectedData->HardcodedOriginalMemory.MemorySize = sizeof(NtCreateFileHard);
	}
	else {
		return STATUS_INVALID_PARAMETER;
	}


	// Copy the data from Function+0x0->Function+FullInstructionSize to the buffer and log the syscall number:
	RtlCopyMemory(ProtectedData->OriginalData, ProtectedData->FunctionDataSSDTEntry, FullInstructionSize);
	ProtectedData->ActualOriginalChecked = FullInstructionSize;
	ProtectedData->SyscallNumber = SyscallNumber;
	return STATUS_SUCCESS;
}


BOOL FreeProtectedFunctions() {
	if (NtQueryDirFileProt.SyscallNumber != 0) {
		RtlFreeUnicodeString(&NtQueryDirFileProt.FunctionName);
	}
	if (NtQueryDirFileExProt.SyscallNumber != 0) {
		RtlFreeUnicodeString(&NtQueryDirFileExProt.FunctionName);
	}
	if (NtQuerySysInfoProt.SyscallNumber != 0) {
		RtlFreeUnicodeString(&NtQuerySysInfoProt.FunctionName);
	}
	if (NtCreateFileProt.SyscallNumber != 0) {
		RtlFreeUnicodeString(&NtCreateFileProt.FunctionName);
	}
	return TRUE;
}


BOOL RtlFindExportedRoutineByNameProtection() {
	PSYSTEM_MODULE KernelBaseAddress = memory_helpers::GetModuleBaseAddressADD("\\SystemRoot\\System32\\ntoskrnl.exe");
	if (KernelBaseAddress == NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver syscalls - Fix RtlFindExportedRoutineByName, kernel base = NULL\n");
		return FALSE;
	}
	if (RtlCompareMemory((PVOID)((ULONG64)KernelBaseAddress->Base + RTLFINDEXP_KERNELOFFSET), RtlExpRtnByNameHard,
		sizeof(RtlExpRtnByNameHard)) != sizeof(RtlExpRtnByNameHard)) {
		if (!memory_transfer::WriteToReadOnlyMemoryADD((PVOID)((ULONG64)KernelBaseAddress->Base + RTLFINDEXP_KERNELOFFSET),
			RtlExpRtnByNameHard, sizeof(RtlExpRtnByNameHard), TRUE)) {
			DbgPrintEx(0, 0, "ProtectionDriver syscalls - Failed to fix RtlFindExportedRoutineByName error/patch\n");
			return FALSE;
		}
	}
	DbgPrintEx(0, 0, "ProtectionDriver syscalls - Successfully fixed RtlFindExportedRoutineByName error/patch\n");
	return TRUE;
}


BOOL MmGetSystemRoutineAddressProtection() {
	PSYSTEM_MODULE KernelBaseAddress = memory_helpers::GetModuleBaseAddressADD("\\SystemRoot\\System32\\ntoskrnl.exe");
	if (KernelBaseAddress == NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver syscalls - Fix MmGetSystemRoutineAddress, kernel base = NULL\n");
		return FALSE;
	}
	if (RtlCompareMemory((PVOID)((ULONG64)KernelBaseAddress->Base + MMGETSYSRTN_KERNELOFFSET), MmGetSysRoutineHard, sizeof(MmGetSysRoutineHard)) != sizeof(MmGetSysRoutineHard)) {
		if (!memory_transfer::WriteToReadOnlyMemoryADD((PVOID)((ULONG64)KernelBaseAddress->Base + MMGETSYSRTN_KERNELOFFSET),
			MmGetSysRoutineHard, sizeof(MmGetSysRoutineHard), TRUE)) {
			DbgPrintEx(0, 0, "ProtectionDriver syscalls - Failed to fix MmGetSystemRoutineAddress error/patch\n");
			return FALSE;
		}
	}
	DbgPrintEx(0, 0, "ProtectionDriver syscalls - Successfully fixed MmGetSystemRoutineAddress error/patch\n");
	return TRUE;
}


ULONG PatternMatchingDetection(PSYSCALL_PROTECT ProtectedFunction) {
	if (memory_helpers::MatchPatternADD(MovJmpPattern, (BYTE*)ProtectedFunction->FunctionDataSSDTEntry, MovJmpMask, strlen(MovJmpMask)) == strlen(MovJmpMask) ||
		memory_helpers::MatchPatternADD(MovJmpRnPattern, (BYTE*)ProtectedFunction->FunctionDataSSDTEntry, MovJmpRnMask, strlen(MovJmpRnMask)) == strlen(MovJmpRnMask)) {
		return MOVJMPREG_ADDROFFS;  // Regular offset is address = r8-13 offset
	}
	if (memory_helpers::MatchPatternADD(PushMovXchgRetPattern, (BYTE*)ProtectedFunction->FunctionDataSSDTEntry, PushMovXchgRetMask, strlen(PushMovXchgRetMask)) == strlen(PushMovXchgRetMask)) {
		return PUSHMOVXCHGRETREG_ADDROFFS;
	}
	if (memory_helpers::MatchPatternADD(PushMovXchgRetRnPattern, (BYTE*)ProtectedFunction->FunctionDataSSDTEntry, PushMovXchgRetRnMask, strlen(PushMovXchgRetRnMask)) == strlen(PushMovXchgRetRnMask)) {
		return PUSHMOVXCHGRET_ADDROFFS;
	}
	return 0;  // No match found
}


NTSTATUS SSDTHookProtection(PSYSCALL_PROTECT ProtectedFunction) {
	PVOID FunctionAddressKernelExport = NULL;
	PVOID FunctionAddressSSDTEntry = NULL;
	PVOID OriginalSSDTEntry = NULL;

	// Check for invalid parameters:
	if (ProtectedFunction == NULL || ProtectedFunction->ActualOriginalChecked == 0 ||
		ProtectedFunction->FunctionAddressKernelExport == NULL || ProtectedFunction->FunctionDataSSDTEntry == NULL ||
		ProtectedFunction->OriginalData == NULL || ProtectedFunction->SyscallNumber == 0 ||
		ProtectedFunction->FunctionName.Buffer == NULL || ProtectedFunction->FunctionName.Length == 0 ||
		ProtectedFunction->FunctionName.MaximumLength == 0) {
		return STATUS_INVALID_PARAMETER;
	}
	OriginalSSDTEntry = ProtectedFunction->FunctionDataSSDTEntry;


	// Use the UNICODE_STRING FunctionName to get the function exported address (kernel base + function RVA):
	if (!RtlFindExportedRoutineByNameProtection() || !MmGetSystemRoutineAddressProtection()) {
		general_helpers::TriggerBlueScreenOfDeath();
		return STATUS_UNSUCCESSFUL;
	}
	FunctionAddressKernelExport = MmGetSystemRoutineAddress(&ProtectedFunction->FunctionName);
	if (ProtectedFunction->FunctionAddressKernelExport != FunctionAddressKernelExport &&
		FunctionAddressKernelExport != NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver syscalls - Current export address (%p) != Initial export address (%p), last value returned from MmGetSystemRoutineAddress was corrupted\n", FunctionAddressKernelExport, ProtectedFunction->FunctionAddressKernelExport);
		ProtectedFunction->FunctionAddressKernelExport = FunctionAddressKernelExport;  // Put true address in the address log
	}


	// Check if the current SSDT entry address is the same as the initial one, if not - "SSDT Hook" to the original function:
	FunctionAddressSSDTEntry = (PVOID)SSDT::CurrentSSDTFuncAddr(ProtectedFunction->SyscallNumber);
	if (FunctionAddressSSDTEntry != ProtectedFunction->FunctionDataSSDTEntry) {
		DbgPrintEx(0, 0, "ProtectionDriver syscalls - Current SSDT entry address (%p) != Initial SSDT entry address (%p), detected SSDT hook\n", FunctionAddressSSDTEntry, ProtectedFunction->FunctionDataSSDTEntry);
		if (ProtectedFunction->FunctionAddressKernelExport != ProtectedFunction->FunctionDataSSDTEntry) {
			ProtectedFunction->FunctionDataSSDTEntry = ProtectedFunction->FunctionAddressKernelExport;
		}
		if (FunctionAddressSSDTEntry != ProtectedFunction->FunctionDataSSDTEntry) {
			if (!NT_SUCCESS(SSDT::SystemServiceDTUnhook(ProtectedFunction->FunctionDataSSDTEntry, ProtectedFunction->SyscallNumber))) {
				DbgPrintEx(0, 0, "ProtectionDriver syscalls - Failed to fix SSDT hook detected in syscall %lu, %wZ\n", ProtectedFunction->SyscallNumber, &ProtectedFunction->FunctionName);
				general_helpers::TriggerBlueScreenOfDeath();
				return STATUS_UNSUCCESSFUL;
			}
		}
	}


	// Check if current address in SSDT entry = address resolved by kernel base + routine RVA, if not - write the latter in the entry:
	if (ProtectedFunction->FunctionDataSSDTEntry != ProtectedFunction->FunctionAddressKernelExport) {
		DbgPrintEx(0, 0, "ProtectionDriver syscalls - Current SSDT entry address (%p) != Initial system service export address (%p), detected SSDT hook\n", FunctionAddressSSDTEntry, ProtectedFunction->FunctionAddressKernelExport);
		if (!NT_SUCCESS(SSDT::SystemServiceDTUnhook(ProtectedFunction->FunctionAddressKernelExport, ProtectedFunction->SyscallNumber))) {
			DbgPrintEx(0, 0, "ProtectionDriver syscalls - Failed to fix SSDT hook detected in syscall %lu, %wZ\n", ProtectedFunction->SyscallNumber, &ProtectedFunction->FunctionName);
			general_helpers::TriggerBlueScreenOfDeath();
			return STATUS_UNSUCCESSFUL;
		}
		ProtectedFunction->FunctionDataSSDTEntry = ProtectedFunction->FunctionAddressKernelExport;
	}


	// Save the actual bytes after resolving new address:
	if (OriginalSSDTEntry != ProtectedFunction->FunctionDataSSDTEntry) {
		RtlCopyMemory(ProtectedFunction->OriginalData, ProtectedFunction->FunctionDataSSDTEntry, ProtectedFunction->ActualOriginalChecked);
	}
	return STATUS_SUCCESS;
}


NTSTATUS SSInlineHookProtection(PSYSCALL_PROTECT ProtectedFunction) {
	SIZE_T LastMatchingByte = 0;


	// Check for invalid parameters:
	if (ProtectedFunction == NULL || ProtectedFunction->ActualOriginalChecked == 0 ||
		ProtectedFunction->FunctionAddressKernelExport == NULL || ProtectedFunction->FunctionDataSSDTEntry == NULL ||
		ProtectedFunction->OriginalData == NULL) {
		return STATUS_INVALID_PARAMETER;
	}


	// Check if memory in system service is the same as the original information (should not be triggered if system call detection worked):
	LastMatchingByte = RtlCompareMemory(ProtectedFunction->OriginalData, ProtectedFunction->FunctionDataSSDTEntry, ProtectedFunction->ActualOriginalChecked);
	if (LastMatchingByte != ProtectedFunction->ActualOriginalChecked) {
		DbgPrintEx(0, 0, "ProtectionDriver syscalls - Current system service data != initial system service data (difference = byte number %zu, range = %llu), detected system service inline hook\n", LastMatchingByte, ProtectedFunction->ActualOriginalChecked);
		if (!memory_transfer::WriteToReadOnlyMemoryADD(ProtectedFunction->FunctionDataSSDTEntry, ProtectedFunction->OriginalData, ProtectedFunction->ActualOriginalChecked, TRUE)) {
			DbgPrintEx(0, 0, "ProtectionDriver syscalls - Failed to fix system service inline hook detected in system service %lu, %wZ\n", ProtectedFunction->SyscallNumber, &ProtectedFunction->FunctionName);
			general_helpers::TriggerBlueScreenOfDeath();
			return STATUS_UNSUCCESSFUL;
		}
	}


	// Check if memory in system service is the same as the hardcoded original information (should not be triggered if system call detection worked):
	LastMatchingByte = RtlCompareMemory(ProtectedFunction->HardcodedOriginalMemory.MemoryBuffer, ProtectedFunction->FunctionDataSSDTEntry, ProtectedFunction->HardcodedOriginalMemory.MemorySize);
	if (LastMatchingByte != ProtectedFunction->HardcodedOriginalMemory.MemorySize) {
		DbgPrintEx(0, 0, "ProtectionDriver syscalls - Current system service data != hardcoded system service data (difference = byte number %zu, range = %llu), detected system service inline hook\n", LastMatchingByte, ProtectedFunction->HardcodedOriginalMemory.MemorySize);
		if (!memory_transfer::WriteToReadOnlyMemoryADD(ProtectedFunction->FunctionDataSSDTEntry, ProtectedFunction->HardcodedOriginalMemory.MemoryBuffer, ProtectedFunction->HardcodedOriginalMemory.MemorySize, TRUE)) {
			DbgPrintEx(0, 0, "ProtectionDriver syscalls - Failed to fix system service inline hook detected in system service %lu, %wZ\n", ProtectedFunction->SyscallNumber, &ProtectedFunction->FunctionName);
			general_helpers::TriggerBlueScreenOfDeath();
			return STATUS_UNSUCCESSFUL;
		}
		RtlCopyMemory(ProtectedFunction->OriginalData, ProtectedFunction->HardcodedOriginalMemory.MemoryBuffer, ProtectedFunction->HardcodedOriginalMemory.MemorySize);
	}
	return STATUS_SUCCESS;
}


PVOID SystemCallsProtection() {
	LARGE_INTEGER TimerNanoCount = { 0 };
	TimerNanoCount.QuadPart = 600000000;  // 600,000,000 units of 100 nano seconds = 60 seconds


	// Initialize the structs used to verify data for the saved functions:
	if (!NT_SUCCESS(InitializeSyscallProtectedFunction(L"NtQueryDirectoryFile", 76, &NtQueryDirFileProt, NTQUERY_SYSCALL1809))) {
		goto Cleaning;
	}
	if (!NT_SUCCESS(InitializeSyscallProtectedFunction(L"NtQueryDirectoryFileEx", 80, &NtQueryDirFileExProt, NTQUERYEX_SYSCALL1809))) {
		goto Cleaning;
	}
	if (!NT_SUCCESS(InitializeSyscallProtectedFunction(L"NtCreateFile", 92, &NtCreateFileProt, NTCREATEFILE_SYSCALL1809))) {
		goto Cleaning;
	}
	if (!NT_SUCCESS(InitializeSyscallProtectedFunction(L"NtQuerySystemInformation", 92, &NtQuerySysInfoProt, NTQUERYSYSINFO_SYSCALL1809))) {
		goto Cleaning;
	}


	// Make an infinite loop to check for any manipulations:
	while (TRUE) {

		// SSDT hook protection:
		if (!NT_SUCCESS(SSDTHookProtection(&NtQueryDirFileProt)) ||
			!NT_SUCCESS(SSDTHookProtection(&NtQueryDirFileExProt)) ||
			!NT_SUCCESS(SSDTHookProtection(&NtCreateFileProt)) ||
			!NT_SUCCESS(SSDTHookProtection(&NtQuerySysInfoProt))) {
			goto Cleaning;
		}


		// System service inline hook protection (with original data + pattern matching of popular hooks):
		if (!NT_SUCCESS(SSInlineHookProtection(&NtQueryDirFileProt)) ||
			!NT_SUCCESS(SSInlineHookProtection(&NtQueryDirFileExProt)) ||
			!NT_SUCCESS(SSInlineHookProtection(&NtCreateFileProt)) ||
			!NT_SUCCESS(SSInlineHookProtection(&NtQuerySysInfoProt))) {
			goto Cleaning;
		}


		// Delay this thread's execution to mimic Sleep() for 5 seconds:
		if (!NT_SUCCESS(KeDelayExecutionThread(KernelMode, FALSE, &TimerNanoCount))) {
			DbgPrintEx(0, 0, "ProtectionDriver syscalls - Failed to delay thread execution\n");
		}
	}

Cleaning:
	if (NtQueryDirFileProt.FunctionName.Buffer != NULL && NtQueryDirFileProt.FunctionName.Length != 0) {
		RtlFreeUnicodeString(&NtQueryDirFileProt.FunctionName);
	}
	if (NtQueryDirFileExProt.FunctionName.Buffer != NULL && NtQueryDirFileExProt.FunctionName.Length != 0) {
		RtlFreeUnicodeString(&NtQueryDirFileExProt.FunctionName);
	}	
	if (NtCreateFileProt.FunctionName.Buffer != NULL && NtCreateFileProt.FunctionName.Length != 0) {
		RtlFreeUnicodeString(&NtCreateFileProt.FunctionName);
	}	
	if (NtQuerySysInfoProt.FunctionName.Buffer != NULL && NtQuerySysInfoProt.FunctionName.Length != 0) {
		RtlFreeUnicodeString(&NtQuerySysInfoProt.FunctionName);
	}
	return NULL;
}