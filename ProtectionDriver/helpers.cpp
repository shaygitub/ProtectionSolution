#include "helpers.h"
#include <bcrypt.h>
#pragma warning(disable : 4996)
#pragma warning(disable : 4244)


NTSTATUS general_helpers::OpenProcessHandleADD(HANDLE* Process, ULONG64 PID) {
	OBJECT_ATTRIBUTES ProcessAttr = { 0 };
	CLIENT_ID ProcessCid = { 0 };
	ProcessCid.UniqueProcess = (HANDLE)PID;
	ProcessCid.UniqueThread = NULL;
	InitializeObjectAttributes(&ProcessAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	return ZwOpenProcess(Process, PROCESS_ALL_ACCESS, &ProcessAttr, &ProcessCid);;
}


NTSTATUS general_helpers::CopyStringAfterCharADD(PUNICODE_STRING OgString, PUNICODE_STRING NewString, WCHAR Char) {
	SIZE_T AfterLength = 0;
	WCHAR* CharOcc = NULL;


	// Check for invalid paramters:
	if (OgString->Length == 0 || OgString->Buffer == NULL) {
		return STATUS_INVALID_PARAMETER;
	}


	// Find last occurance and copy string after it:
	CharOcc = wcsrchr(OgString->Buffer, Char);
	if (CharOcc == NULL) {
		NewString->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, OgString->Length, 'HlCs');
		if (NewString->Buffer == NULL) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}
		NewString->Length = OgString->Length;
		NewString->MaximumLength = OgString->MaximumLength;
		RtlCopyMemory(NewString->Buffer, OgString->Buffer, OgString->Length);
		return STATUS_SUCCESS;
	}
	else {
		AfterLength = OgString->Length - ((CharOcc - OgString->Buffer + 1) * sizeof(WCHAR));  // +1 to get to the character AFTER Char
		if (AfterLength > 0) {
			NewString->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, AfterLength, 0x53625374);

			if (NewString->Buffer != NULL) {
				NewString->Length = (USHORT)AfterLength;
				NewString->MaximumLength = (USHORT)AfterLength;
				RtlCopyMemory(NewString->Buffer, CharOcc + 1, AfterLength);
				return STATUS_SUCCESS;
			}
			else {
				return STATUS_MEMORY_NOT_ALLOCATED;
			}
		}
		else {
			return STATUS_INVALID_PARAMETER;
		}
	}
}


BOOL general_helpers::CompareUnicodeStringsADD(PUNICODE_STRING First, PUNICODE_STRING Second, USHORT CheckLength) {
	// Check for invalid parameters:
	if (First == NULL || Second == NULL || First->Buffer == NULL || Second->Buffer == NULL || Second->Length != First->Length) {
		return FALSE;
	}


	// Compare strings:
	if (CheckLength == 0) {
		for (USHORT i = 0; i < First->Length / sizeof(WCHAR); i++) {
			if (First->Buffer[i] != Second->Buffer[i]) {
				return FALSE;
			}
		}
	}
	else {
		for (USHORT i = 0; i < CheckLength / sizeof(WCHAR); i++) {
			if (First->Buffer[i] != Second->Buffer[i]) {
				return FALSE;
			}
		}
	}
	return TRUE;
}


BOOL general_helpers::IsExistFromIndexADD(PUNICODE_STRING Inner, PUNICODE_STRING Outer, USHORT StartIndex) {
	// Check for invalid parameters:
	if (Inner->Length == 0 || Outer->Length == 0 || (StartIndex * sizeof(WCHAR)) + Inner->Length > Outer->Length || Inner->Buffer == NULL || Outer->Buffer == NULL) {
		return FALSE;
	}

	// Compare strings:
	for (USHORT i = 0; i < Inner->Length / sizeof(WCHAR); i++) {
		if (Inner->Buffer[i] != Outer->Buffer[i + StartIndex]) {
			return FALSE;
		}
	}
	return TRUE;
}


void general_helpers::PrintUnicodeStringADD(PUNICODE_STRING Str) {
	if (Str != NULL && Str->Buffer != NULL && Str->Length != 0) {
		DbgPrintEx(0, 0, "-+-+-\n");
		for (int stri = 0; stri <= Str->Length / sizeof(WCHAR); stri++) {
			switch (Str->Buffer[stri]) {
			case L'\0':
				DbgPrintEx(0, 0, "Null Terminator\n"); break;
			case L'\n':
				DbgPrintEx(0, 0, "New Line\n"); break;
			default:
				DbgPrintEx(0, 0, "%c\n", Str->Buffer[stri]); break;
			}
		}
		DbgPrintEx(0, 0, "+-+-+\n");
	}
}


NTSTATUS general_helpers::GetPidNameFromListADD(ULONG64* ProcessId, char ProcessName[15], BOOL NameGiven) {
	char CurrentProcName[15] = { 0 };
	LIST_ENTRY* CurrentList = NULL;
	LIST_ENTRY* PreviousList = NULL;
	LIST_ENTRY* NextList = NULL;
	LIST_ENTRY* LastProcessFlink = &((PACTEPROCESS)PsInitialSystemProcess)->ActiveProcessLinks;
	PACTEPROCESS CurrentProcess = (PACTEPROCESS)PsInitialSystemProcess;
	PreviousList = &CurrentProcess->ActiveProcessLinks;
	CurrentList = PreviousList->Flink;
	CurrentProcess = (PACTEPROCESS)((ULONG64)CurrentList - ((ULONG64)&CurrentProcess->ActiveProcessLinks - (ULONG64)CurrentProcess));
	NextList = CurrentList->Flink;

	while (CurrentList != LastProcessFlink) {
		if (!NameGiven) {
			if ((ULONG64)CurrentProcess->UniqueProcessId == *ProcessId) {
				RtlCopyMemory(ProcessName, &CurrentProcess->ImageFileName, 15);
				DbgPrintEx(0, 0, "KMDFdriver GetPidNameFromListADD - Found name %s for PID %llu\n", ProcessName, *ProcessId);
				return STATUS_SUCCESS;
			}
		}
		else {
			RtlCopyMemory(CurrentProcName, &CurrentProcess->ImageFileName, 15);
			if (_stricmp(CurrentProcName, ProcessName) == 0) {
				*ProcessId = (ULONG64)CurrentProcess->UniqueProcessId;
				DbgPrintEx(0, 0, "KMDFdriver GetPidNameFromListADD - Found PID %llu for name %s\n", *ProcessId, ProcessName);
				return STATUS_SUCCESS;
			}
			RtlZeroMemory(CurrentProcName, 15);
		}
		PreviousList = CurrentList;
		CurrentList = NextList;
		NextList = CurrentList->Flink;
		CurrentProcess = (PACTEPROCESS)((ULONG64)CurrentList - ((ULONG64)&CurrentProcess->ActiveProcessLinks - (ULONG64)CurrentProcess));
	}
	return STATUS_NOT_FOUND;
}


ULONG general_helpers::GetActualLengthADD(PUNICODE_STRING String) {
	ULONG StringLength = 0;
	if (String == NULL || String->Buffer == NULL) {
		return 0;
	}
	while (String->Buffer[StringLength] != L'\0') {
		StringLength++;
	}
	String->Length = (USHORT)(StringLength * sizeof(WCHAR));
	String->MaximumLength = (USHORT)(StringLength * sizeof(WCHAR));
	return StringLength;
}


typedef void(*EmptyFunction)(VOID);
void general_helpers::ExecuteInstructionsADD(BYTE Instructions[], SIZE_T InstructionsSize) {
	BYTE RetOpcode = 0xC3;
	EmptyFunction FunctionCall = NULL;
	PVOID InstructionsPool = ExAllocatePoolWithTag(NonPagedPool, InstructionsSize + 1, 'TpIe');
	if (InstructionsPool != NULL) {
		RtlCopyMemory(InstructionsPool, Instructions, InstructionsSize);
		RtlCopyMemory((PVOID)((ULONG64)InstructionsPool + InstructionsSize), &RetOpcode, 1);  // call will push return address
		FunctionCall = (EmptyFunction)InstructionsPool;
		FunctionCall();
	}
}


NTSTATUS general_helpers::CreateDataHashADD(PVOID DataToHash, ULONG SizeOfDataToHash, LPCWSTR HashName,
	PVOID* HashedDataOutput, ULONG* HashedDataLength) {
	/*
	Note: hash name is the documented macro for the type of encryption
	documented in https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
	*/
	NTSTATUS Status = STATUS_SUCCESS;
	BCRYPT_ALG_HANDLE HashAlgorithm = { 0 };
	BCRYPT_HASH_HANDLE HashHandle = { 0 };
	ULONG HashObjectLength = 0;
	ULONG HashObjLengthWritten = 0;
	ULONG HashDataLength = 0;
	ULONG HashDataLengthWritten = 0;
	PVOID HashObject = NULL;
	PVOID HashedData = NULL;
	BOOL HashHandleCreated = FALSE;
	BOOL HashProviderCreated = FALSE;


	// Make sure no invalid parameters are provided (no need to enforce outputed hashed data length):
	if (HashName == NULL || DataToHash == NULL || HashedDataOutput == NULL) {
		return STATUS_INVALID_PARAMETER;
	}


	// Create the hashing algorithm provider handle to hash the data:
	Status = BCryptOpenAlgorithmProvider(&HashAlgorithm, HashName, NULL, 0);
	if (!NT_SUCCESS(Status)) {
		goto CleanUp;
	}
	HashProviderCreated = TRUE;


	// Get the needed length for the hashing object and allocate a non-paged pool for the object:
	Status = BCryptGetProperty(HashAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&HashObjectLength,
		sizeof(HashObjectLength), &HashObjLengthWritten, 0);
	if (!NT_SUCCESS(Status) || HashObjLengthWritten != sizeof(HashObjectLength)) {
		if (NT_SUCCESS(Status)) {
			Status = STATUS_INFO_LENGTH_MISMATCH;  // In this case not all the data size was written
		}
		goto CleanUp;
	}
	HashObject = ExAllocatePoolWithTag(NonPagedPool, HashObjectLength, 'ThOp');
	if (HashObject == NULL) {
		Status = STATUS_MEMORY_NOT_ALLOCATED;
		goto CleanUp;
	}


	// Create the hashing object used to hash the actual data:
	Status = BCryptCreateHash(HashAlgorithm, &HashHandle, (PUCHAR)HashObject, HashObjectLength, NULL, 0, 0);
	if (!NT_SUCCESS(Status)) {
		goto CleanUp;
	}
	HashHandleCreated = TRUE;


	// Get the hashed data size and allocate a non-paged pool for the hashed data:
	Status = BCryptGetProperty(HashAlgorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&HashDataLength,
		sizeof(HashDataLength), &HashDataLengthWritten, 0);
	if (!NT_SUCCESS(Status) || HashDataLengthWritten != sizeof(HashDataLength)) {
		if (NT_SUCCESS(Status)) {
			Status = STATUS_INFO_LENGTH_MISMATCH;  // In this case not all the data size was written
		}
		goto CleanUp;
	}
	HashedData = ExAllocatePoolWithTag(NonPagedPool, HashDataLength, 'ThDp');
	if (HashedData == NULL) {
		Status = STATUS_MEMORY_NOT_ALLOCATED;
		goto CleanUp;
	}


	// Hash the actual data:
	Status = BCryptHashData(HashHandle, (PUCHAR)DataToHash, SizeOfDataToHash, 0);
	if (!NT_SUCCESS(Status)) {
		goto CleanUp;
	}


	// Get the hash value (hash handle cannot be reused after this operation) and return it to caller:
	Status = BCryptFinishHash(HashHandle, (PUCHAR)HashedData, HashDataLength, 0);
	if (!NT_SUCCESS(Status)) {
		goto CleanUp;
	}


	// Clean up and return successfully:
	CleanUp:
	if (HashHandleCreated) {
		BCryptDestroyHash(HashHandle);
	}
	if (HashProviderCreated) {
		BCryptCloseAlgorithmProvider(HashAlgorithm, 0);
	}
	if (HashObject != NULL) {
		ExFreePool(HashObject);
	}
	if (HashedData != NULL && !NT_SUCCESS(Status)) {
		ExFreePool(HashedData);  // Note: dont free HashedData if succeeded, will hold the hashed data
		HashedData = NULL;
		HashedDataLength = 0;
	}
	*HashedDataOutput = HashedData;
	if (HashedDataLength != NULL) {
		*HashedDataLength = HashDataLength;
	}
	return Status;
}


void general_helpers::TriggerBlueScreenOfDeath() {
	IoRaiseHardError(NULL, NULL, NULL);
	RtlCopyMemory((PVOID)0x1234567890123456, (PVOID)0x1234567890123456, 999999);  // Trigger mostly possible BSoD if last one did not trigger
}




BOOL memory_helpers::FreeAllocatedMemoryADD(PEPROCESS EpDst, ULONG OldState, PVOID BufferAddress, SIZE_T BufferSize) {
	KAPC_STATE DstState = { 0 };
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	MEMORY_BASIC_INFORMATION MemoryBasic = { 0 };


	// Check for invalid paramters:
	if (EpDst == NULL || BufferAddress == NULL || BufferSize == 0) {
		return NULL;
	}


	// Query the memory area to get newer status update:
	KeStackAttachProcess(EpDst, &DstState);
	Status = ZwQueryVirtualMemory(ZwCurrentProcess(), BufferAddress, MemoryBasicInformation, &MemoryBasic, sizeof(MemoryBasic), NULL);
	if (!NT_SUCCESS(Status)) {
		KeUnstackDetachProcess(&DstState);
		return FALSE;
	}


	// Free memory if needed:
	if (MemoryBasic.AllocationBase == BufferAddress) {
		switch (MemoryBasic.State) {
		case MEM_COMMIT:
			if (!(OldState & MEM_RESERVE)) {
				Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &BufferAddress, &BufferSize, MEM_RELEASE);  // Release the unused memory
			}
			else {
				Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &BufferAddress, &BufferSize, MEM_DECOMMIT);  // De-commit the unused memory
			}
			KeUnstackDetachProcess(&DstState);
			if (!NT_SUCCESS(Status)) {
				return FALSE;
			}
			return TRUE;

		case MEM_RESERVE:
			if (!(OldState & MEM_RESERVE)) {
				Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &BufferAddress, &BufferSize, MEM_RELEASE);  // Release the unused memory
			}
			KeUnstackDetachProcess(&DstState);
			if (!NT_SUCCESS(Status)) {
				return FALSE;
			}
			return TRUE;

		default:
			KeUnstackDetachProcess(&DstState);  // detach from the destination process
			return TRUE;
		}
	}
	else {
		KeUnstackDetachProcess(&DstState);
		return TRUE;
	}
}


PVOID memory_helpers::AllocateMemoryADD(PVOID InitialAddress, SIZE_T AllocSize, KAPC_STATE* CurrState, ULONG_PTR ZeroBits) {
	MEMORY_BASIC_INFORMATION MemoryBasic = { 0 };
	PVOID AllocationAddress = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;


	// Check for invalid paramters:
	if (InitialAddress == NULL || AllocSize == 0) {
		return NULL;
	}


	// Initial query of memory (to confirm state and other parameters):
	__try {
		ProbeForRead(InitialAddress, AllocSize, sizeof(UCHAR));
		Status = ZwQueryVirtualMemory(ZwCurrentProcess(), InitialAddress, MemoryBasicInformation, &MemoryBasic, sizeof(MemoryBasic), NULL);

		if (!NT_SUCCESS(Status)) {
			KeUnstackDetachProcess(CurrState);
			return NULL;
		}
	}

	__except (STATUS_ACCESS_VIOLATION) {
		KeUnstackDetachProcess(CurrState);
		return NULL;
	}


	// Act upon initial memory status:
	if (MemoryBasic.Protect & PAGE_NOACCESS) {
		ChangeProtectionSettingsADD(ZwCurrentProcess(), InitialAddress, (ULONG)AllocSize, PAGE_READWRITE, MemoryBasic.Protect);
	}


	// Set the initial allocation base for each memory state:
	if (MemoryBasic.State & MEM_FREE) {
		AllocationAddress = InitialAddress;
	}

	else if (MemoryBasic.State & MEM_RESERVE) {
		AllocationAddress = MemoryBasic.AllocationBase;

		// Verify region size:
		if (AllocSize > MemoryBasic.RegionSize) {
			Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &MemoryBasic.AllocationBase, &MemoryBasic.RegionSize, MEM_RELEASE);
			if (!NT_SUCCESS(Status)) {
				KeUnstackDetachProcess(CurrState);
				return NULL;
			}

			Status = ZwQueryVirtualMemory(ZwCurrentProcess(), InitialAddress, MemoryBasicInformation, &MemoryBasic, sizeof(MemoryBasic), NULL);
			if (!NT_SUCCESS(Status)) {
				KeUnstackDetachProcess(CurrState);
				return NULL;
			}

			AllocationAddress = InitialAddress;
		}
	}

	else {
		Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &MemoryBasic.AllocationBase, &MemoryBasic.RegionSize, MEM_RELEASE);
		if (!NT_SUCCESS(Status)) {
			KeUnstackDetachProcess(CurrState);
			return NULL;
		}

		Status = ZwQueryVirtualMemory(ZwCurrentProcess(), InitialAddress, MemoryBasicInformation, &MemoryBasic, sizeof(MemoryBasic), NULL);
		if (!NT_SUCCESS(Status)) {
			KeUnstackDetachProcess(CurrState);
			return NULL;
		}

		AllocationAddress = InitialAddress;
	}


	// Verify updated region size:
	if (AllocSize > MemoryBasic.RegionSize) {
		KeUnstackDetachProcess(CurrState);
		return NULL;
	}


	// Allocate the actual memory:
	AllocationAddress = CommitMemoryRegionsADD(ZwCurrentProcess(), AllocationAddress, AllocSize, PAGE_READWRITE, NULL, ZeroBits);
	KeUnstackDetachProcess(CurrState);
	return AllocationAddress;
}


ULONG64 memory_helpers::GetHighestUserModeAddrADD() {
	UNICODE_STRING MaxUserSym;
	RtlInitUnicodeString(&MaxUserSym, L"MmHighestUserAddress");
	return (ULONG64)MmGetSystemRoutineAddress(&MaxUserSym);
}


PVOID memory_helpers::FindUnusedMemoryADD(BYTE* SearchSection, ULONG SectionSize, SIZE_T NeededLength) {
	for (ULONG sectioni = 0, sequencecount = 0; sectioni < SectionSize; sectioni++) {
		if (SearchSection[sectioni] == 0x90 || SearchSection[sectioni] == 0xCC) {
			sequencecount++;
		}
		else {
			sequencecount = 0;  // If sequence does not include nop/int3 instruction for long enough - start a new sequence
		}
		if (sequencecount == NeededLength) {
			return (PVOID)((ULONG64)SearchSection + sectioni - SectionSize + 1);  // Get starting address of the matching sequence
		}
	}
	return NULL;
}


PSYSTEM_MODULE memory_helpers::GetModuleBaseAddressADD(const char* ModuleName) {
	PSYSTEM_MODULE_INFORMATION SystemModulesInfo = NULL;
	PSYSTEM_MODULE CurrentSystemModule = NULL;
	ULONG InfoSize = 0;
	// PVOID ModuleBaseAddress = NULL;

	NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, 0, InfoSize, &InfoSize);
	if (InfoSize == 0) {
		DbgPrintEx(0, 0, "KMDFdriver GetModuleBaseAddressADD - did not return the needed size\n");
		return NULL;
	}
	SystemModulesInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(PagedPool, InfoSize, 'MbAp');
	if (SystemModulesInfo == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver GetModuleBaseAddressADD - cannot allocate memory for system modules information\n");
		return NULL;
	}
	Status = ZwQuerySystemInformation(SystemModuleInformation, SystemModulesInfo, InfoSize, &InfoSize);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "KMDFdriver GetModuleBaseAddressADD - query failed with status 0x%x\n", Status);
		ExFreePool(SystemModulesInfo);
		return NULL;
	}


	// Iterate list:
	for (ULONG modulei = 0; modulei < SystemModulesInfo->ModulesCount; ++modulei){
		CurrentSystemModule = &SystemModulesInfo->Modules[modulei];
		if (_stricmp(CurrentSystemModule->ImageName, ModuleName) == 0) {
			// ModuleBaseAddress = CurrentSystemModule->Base;
			ExFreePool(SystemModulesInfo);
			return CurrentSystemModule;
		}
	}
	return NULL;
}


PVOID memory_helpers::GetTextSectionOfSystemModuleADD(PVOID ModuleBaseAddress, ULONG* TextSectionSize) {
	PIMAGE_SECTION_HEADER TextSectionBase = NULL;
	if (ModuleBaseAddress == NULL) {
		return NULL;
	}
	TextSectionBase = memory_helpers::GetSectionHeaderFromNameADD(ModuleBaseAddress, ".text");
	if (TextSectionBase == NULL) {
		return NULL;
	}

	if (TextSectionSize != NULL) {
		*TextSectionSize = TextSectionBase->Misc.VirtualSize;
	}
	return (PVOID)((ULONG64)ModuleBaseAddress + TextSectionBase->VirtualAddress);
}


PIMAGE_SECTION_HEADER memory_helpers::GetSectionHeaderFromNameADD(PVOID ModuleBaseAddress, const char* SectionName) {
	if (ModuleBaseAddress == NULL || SectionName == NULL) {
		return NULL;
	}
	PIMAGE_DOS_HEADER DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleBaseAddress);
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((ULONG64)ModuleBaseAddress + DosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER CurrentSection = IMAGE_FIRST_SECTION(NtHeader);
	for (ULONG sectioni = 0; sectioni < NtHeader->FileHeader.NumberOfSections; ++sectioni) {
		if (strcmp((char*)CurrentSection->Name, SectionName)) {
			return CurrentSection;
		}
		++CurrentSection;
	}
	return NULL;
}


BOOL memory_helpers::ChangeProtectionSettingsADD(HANDLE ProcessHandle, PVOID Address, ULONG Size, ULONG ProtSettings, ULONG OldProtect) {
	MEMORY_BASIC_INFORMATION MemoryInfo = { 0 };
	NTSTATUS Status = STATUS_UNSUCCESSFUL;


	// Check for invalid parameters:
	if (ProcessHandle == NULL || Address == NULL || Size == 0) {
		return FALSE;
	}


	// Change the protection settings of the whole memory range:
	__try {
		ProbeForRead(Address, Size, sizeof(UCHAR));
		Status = ZwProtectVirtualMemory(ProcessHandle, &Address, &Size, ProtSettings, &OldProtect);
		if (!NT_SUCCESS(Status)) {
			return FALSE;
		}
	}
	__except (STATUS_ACCESS_VIOLATION) {
		return FALSE;
	}


	// Query to verify that changes were done:
	__try {
		ProbeForRead(Address, Size, sizeof(UCHAR));
		Status = ZwQueryVirtualMemory(ProcessHandle, Address, MemoryBasicInformation, &MemoryInfo, sizeof(MemoryInfo), NULL);
		if (!NT_SUCCESS(Status)) {
			return TRUE;
		}
	}
	__except (STATUS_ACCESS_VIOLATION) {
		return TRUE;
	}

	if ((MemoryInfo.Protect & ProtSettings) && !(MemoryInfo.Protect & PAGE_GUARD || MemoryInfo.Protect & PAGE_NOACCESS)) {
		return FALSE;
	}
	return TRUE;
}


PVOID memory_helpers::CommitMemoryRegionsADD(HANDLE ProcessHandle, PVOID Address, SIZE_T Size, ULONG AllocProt, PVOID ExistingAllocAddr, ULONG_PTR ZeroBit) {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	MEMORY_BASIC_INFORMATION MemoryInfo = { 0 };


	// Check for invalid parameters:
	if (ProcessHandle == NULL || Address == NULL || Size == 0) {
		return NULL;
	}


	// Allocate the actual needed pages and save them for committing later:
	if (ExistingAllocAddr != NULL) {
		Address = ExistingAllocAddr;
	}
	if (Address != ExistingAllocAddr) {
		__try {
			ProbeForRead(Address, Size, sizeof(UCHAR));
			Status = ZwAllocateVirtualMemory(ProcessHandle, &Address, ZeroBit, &Size, MEM_RESERVE, PAGE_NOACCESS);
		}
		__except (STATUS_ACCESS_VIOLATION) {
			return NULL;
		}

		if (!NT_SUCCESS(Status)) {
			Address = NULL;  // Required to tell the system to choose where to allocate the memory
			ZeroBit = 0;
			Status = ZwAllocateVirtualMemory(ProcessHandle, &Address, ZeroBit, &Size, MEM_RESERVE, PAGE_NOACCESS);  // Size and Address are alligned here after the first call
			if (!NT_SUCCESS(Status)) {
				return NULL;
			}
		}
	}


	// Allocate the range of pages in processes virtual memory with the required allocation type and protection settings:
	Status = ZwAllocateVirtualMemory(ProcessHandle, &Address, ZeroBit, &Size, MEM_COMMIT, AllocProt);
	if (!NT_SUCCESS(Status)) {
		if (Address != ExistingAllocAddr) {
			ZwFreeVirtualMemory(ProcessHandle, &Address, &Size, MEM_RELEASE);  // Release the unused memory
		}
		else {
			ZwFreeVirtualMemory(ProcessHandle, &Address, &Size, MEM_DECOMMIT);  // De-commit the unused memory
		}
		return NULL;
	}


	// Query to verify the change of memory state:
	Status = ZwQueryVirtualMemory(ProcessHandle, Address, MemoryBasicInformation, &MemoryInfo, sizeof(MemoryInfo), NULL);
	if (!NT_SUCCESS(Status)) {
		return Address;
	}

	if (!(MemoryInfo.State & MEM_COMMIT)) {
		return NULL;
	}
	return Address;
}


ULONG memory_helpers::MatchPatternADD(const BYTE CompareTo[], BYTE ComparingData[], const char* CompareMask, ULONG64 CompareSize) {
	ULONG64 CompareIndex = 0;
	if (CompareTo == NULL || ComparingData == NULL || CompareMask == 0 || CompareSize == 0) {
		return 0;
	}
	for (; CompareIndex < CompareSize; CompareIndex++) {
		if (CompareTo[CompareIndex] != ComparingData[CompareIndex] &&
			CompareMask[CompareIndex] == 'x') {
			return CompareIndex;
		}
	}
	return CompareIndex;
}




BOOL memory_transfer::WriteMemoryADD(PVOID WriteAddress, PVOID SourceBuffer, SIZE_T WriteSize) {
	if (WriteAddress == NULL || SourceBuffer == NULL || WriteSize == 0) {
		return FALSE;
	}
	if (!RtlCopyMemory(WriteAddress, SourceBuffer, WriteSize)) {
		return FALSE;
	}
	return TRUE;
}


BOOL memory_transfer::WriteToReadOnlyMemoryADD(PVOID Address, PVOID Buffer, SIZE_T Size, BOOL IsWrite) {
	PMDL MemoryDescriptor = NULL;
	PVOID MappedMemory = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;


	// Check for invalid parameters:
	if (Address == NULL || Buffer == NULL || Size == 0) {
		return FALSE;
	}


	// Create a memory descriptor for the memory range for operation on memory:
	if (IsWrite) {
		MemoryDescriptor = IoAllocateMdl(Address, (ULONG)Size, FALSE, FALSE, NULL);
	}
	else {
		MemoryDescriptor = IoAllocateMdl(Buffer, (ULONG)Size, FALSE, FALSE, NULL);
	}
	if (MemoryDescriptor == NULL) {
		return FALSE;
	}


	// Lock the pages in physical memory (similar to NonPaged pool concept):
	MmProbeAndLockPages(MemoryDescriptor, KernelMode, IoReadAccess);


	// Map the memory pages into system virtual memory:
	MappedMemory = MmMapLockedPagesSpecifyCache(MemoryDescriptor, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	if (MappedMemory == NULL) {
		MmUnlockPages(MemoryDescriptor);
		IoFreeMdl(MemoryDescriptor);
		return FALSE;
	}


	// Set the protection settings of the memory range to be both writeable and readable:
	Status = MmProtectMdlSystemAddress(MemoryDescriptor, PAGE_READWRITE);
	if (!NT_SUCCESS(Status)) {
		MmUnmapLockedPages(MappedMemory, MemoryDescriptor);
		MmUnlockPages(MemoryDescriptor);
		IoFreeMdl(MemoryDescriptor);
		return FALSE;
	}


	// Write/Read into the mapped pages:
	if (IsWrite) {
		if (!memory_transfer::WriteMemoryADD(MappedMemory, Buffer, Size)) {
			MmUnmapLockedPages(MappedMemory, MemoryDescriptor);
			MmUnlockPages(MemoryDescriptor);
			IoFreeMdl(MemoryDescriptor);
			return FALSE;
		}
	}
	else {
		if (!memory_transfer::WriteMemoryADD(Address, MappedMemory, Size)) {
			MmUnmapLockedPages(MappedMemory, MemoryDescriptor);
			MmUnlockPages(MemoryDescriptor);
			IoFreeMdl(MemoryDescriptor);
			return FALSE;
		}
	}
	MmUnmapLockedPages(MappedMemory, MemoryDescriptor);
	MmUnlockPages(MemoryDescriptor);
	IoFreeMdl(MemoryDescriptor);
	return TRUE;
}


NTSTATUS memory_transfer::UserToKernelADD(PEPROCESS SrcProcess, PVOID UserAddress, PVOID KernelAddress, SIZE_T Size, BOOL IsAttached) {
	KAPC_STATE SrcState = { 0 };


	// Check for invalid parameters:
	if (SrcProcess == NULL || UserAddress == NULL || KernelAddress == NULL || Size == 0) {
		return STATUS_INVALID_PARAMETER;
	}


	// Attach to the usermode process if needed:
	if (!IsAttached) {
		KeStackAttachProcess(SrcProcess, &SrcState);
	}


	// Perform the transfer:
	__try {
		ProbeForRead(UserAddress, Size, sizeof(UCHAR));
		RtlCopyMemory(KernelAddress, UserAddress, Size);
		if (!IsAttached) {
			KeUnstackDetachProcess(&SrcState);
		}
		return STATUS_SUCCESS;
	}

	__except (STATUS_ACCESS_VIOLATION) {
		if (!IsAttached) {
			KeUnstackDetachProcess(&SrcState);
		}
		return STATUS_ACCESS_VIOLATION;
	}
}




NTSTATUS memory_transfer::KernelToUserADD(PEPROCESS DstProcess, PVOID KernelAddress, PVOID UserAddress, SIZE_T Size, BOOL IsAttached) {
	KAPC_STATE DstState = { 0 };



	// Check for invalid parameters:
	if (DstProcess == NULL || KernelAddress == NULL || UserAddress == NULL || Size == 0) {
		return STATUS_INVALID_PARAMETER;
	}


	// Attach to the usermode process if needed:
	if (!IsAttached) {
		KeStackAttachProcess(DstProcess, &DstState);
	}


	// Perform the transfer:
	__try {
		ProbeForRead(UserAddress, Size, sizeof(UCHAR));
		RtlCopyMemory(UserAddress, KernelAddress, Size);
		if (!IsAttached) {
			KeUnstackDetachProcess(&DstState);
		}
		return STATUS_SUCCESS;
	}

	__except (STATUS_ACCESS_VIOLATION) {
		if (!IsAttached) {
			KeUnstackDetachProcess(&DstState);
		}
		return STATUS_ACCESS_VIOLATION;
	}
}