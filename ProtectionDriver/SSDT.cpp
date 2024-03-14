#include "syscalls.h"
#include "SSDTGlobals.h"
#include "helpers.h"
#include "VulnurableList.h"
#include <bcrypt.h>
#pragma warning(disable : 4996)


ULONG SSDT::GetSystemCallIndex(PUNICODE_STRING SystemServiceName) {
	PVOID SystemServiceAddress = MmGetSystemRoutineAddress(SystemServiceName);
	if (SystemServiceAddress == NULL) {
		return 0;
	}
	return (*(PULONG)((PUCHAR)SystemServiceAddress + 1));
}


void SSDT::EnableWriteProtection(KIRQL CurrentIRQL) {
	ULONG64 cr0 = __readcr0() | 0x10000;
	_enable();  // Enable interrupts, mightve interrupted the process
	__writecr0(cr0);
	KeLowerIrql(CurrentIRQL);
}


KIRQL SSDT::DisableWriteProtection() {
	KIRQL CurrentIRQL = KeRaiseIrqlToDpcLevel();
	ULONG64 cr0 = __readcr0() & 0xfffffffffffeffff;  // Assumes processor is AMD64
	__writecr0(cr0);
	_disable();    // Disable interrupts
	return CurrentIRQL;
}


ULONG64 SSDT::CurrentSSDTFuncAddr(ULONG SyscallNumber) {
	LONG SystemServiceValue = 0;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)KiServiceDescriptorTable->ServiceTableBase;
	SystemServiceValue = ServiceTableBase[SyscallNumber];
	SystemServiceValue = SystemServiceValue >> 4;
	return (ULONG64)SystemServiceValue + (ULONG64)ServiceTableBase;
}


ULONG64 SSDT::GetServiceDescriptorTable() {
	ULONG64  KiSystemCall64 = __readmsr(0xC0000082);	// Get the address of nt!KeSystemCall64
	ULONG64  KiSystemServiceRepeat = 0;
	INT32 Limit = 4096;
	for (int i = 0; i < Limit; i++) {
		if (*(PUINT8)(KiSystemCall64 + i) == 0x4C
			&& *(PUINT8)(KiSystemCall64 + i + 1) == 0x8D
			&& *(PUINT8)(KiSystemCall64 + i + 2) == 0x15) {
			KiSystemServiceRepeat = KiSystemCall64 + i;  // Got stub of ServiceDescriptorTable from KiSystemServiceRepeat refrence
			return (ULONG64)(*(PINT32)(KiSystemServiceRepeat + 3) + KiSystemServiceRepeat + 7);	 // Convert relative address to absolute address
		}
	}

	return NULL;
}


ULONG SSDT::GetOffsetFromSSDTBase(ULONG64 FunctionAddress) {
	PULONG ServiceTableBase = (PULONG)KiServiceDescriptorTable->ServiceTableBase;
	return ((ULONG)(FunctionAddress - (ULONGLONG)ServiceTableBase)) << 4;
}


NTSTATUS SSDT::SystemServiceDTUnhook(PVOID ActualSystemService, ULONG SyscallNumber) {
	PULONG ServiceTableBase = NULL;
	KIRQL CurrentIRQL = NULL;
	ULONG SSDTEntryValue = NULL;


	// Check for invalid parameters:
	if (ActualSystemService == NULL || SyscallNumber == 0) {
		DbgPrintEx(0, 0, "ProtectionDriver SSDT unhook failed (invalid parameters: %p, %lu)\n", ActualSystemService, SyscallNumber);
		return STATUS_INVALID_PARAMETER;
	}

	
	// Unhook the SSDT entry to point to the initial address of the system service:
	ServiceTableBase = (PULONG)KiServiceDescriptorTable->ServiceTableBase;
	CurrentIRQL = SSDT::DisableWriteProtection();
	SSDTEntryValue = SSDT::GetOffsetFromSSDTBase((ULONG64)ActualSystemService);
	SSDTEntryValue &= 0xFFFFFFF0;
	SSDTEntryValue += ServiceTableBase[SyscallNumber] & 0x0F;
	ServiceTableBase[SyscallNumber] = SSDTEntryValue;
	SSDT::EnableWriteProtection(CurrentIRQL);
	DbgPrintEx(0, 0, "ProtectionDriver SSDT unhook %lu succeeded\n", SyscallNumber);
	return STATUS_SUCCESS;
}


NTSTATUS SSDT::SystemServiceDTHook(PVOID HookingFunction, ULONG Tag) {
	/*
	Business logic of hook:
	1) Get address of ServiceDescriptorTable with specific pattern matching in the kernel code section (.text)
	2) Get the address of the current function (will be put in *OriginalFunction) from the SSDT
	3) Add the address of the hooking function to the data of the trampoline dummy (SSDT entry is only 32 bits in x64, need to create stub hook and kump to that)
	4) Find an area inside the kernel's code section (.text) that can hold the data of the trampoline dummy hook (check sequence of nops big enough)
	5) Map the kernel's image into writeable memory, change protection settings to be able to write dummy hook into the kernel, write it into the kernel
	6) Disable WP (Write-Protected), patch the SSDT entry, enable WP protections
	7) Unmap the kernel image to save changes
	*/


	BYTE DummyTrampoline[] = { 0x50,  // push rax
							   0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rax, HookingFunction
							   0x48, 0x87, 0x04, 0x24,  // xchg QWORD PTR [rsp],rax
							   0xc3 };  // ret (jmp to HookingFunction)
	PVOID TrampolineSection = NULL;  // Will hold the matching sequence of nop/int3 instructions for the trampoline hook
	PVOID KernelMapping = NULL;
	PMDL KernelModuleDescriptor = NULL;
	PULONG ServiceTableBase = NULL;  // Used to modify the actual entry in the SSDT
	KIRQL CurrentIRQL = NULL;
	ULONG SSDTEntryValue = 0;
	PVOID KernelImageBaseAddress = NULL;
	PVOID KernelTextSection = NULL;
	ULONG TextSectionSize = 0;
	PVOID* OriginalFunction = NULL;
	ULONG SyscallNumber = 0;


	// Check for invalid parameters:
	if (HookingFunction == NULL || Tag == 0) {
		DbgPrintEx(0, 0, "ProtectionDriver SSDT safe-hook failed (invalid parameters: %p, %lu)\n", HookingFunction, Tag);
		return STATUS_INVALID_PARAMETER;
	}


	// Make preperations for SSDT hook - get SSDT address, get ntoskrnl.exe image base address and get code section (.text section) address of the kernel:
	if (KiServiceDescriptorTable == NULL) {
		KiServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)SSDT::GetServiceDescriptorTable();
	}
	if (KiServiceDescriptorTable == NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver SSDT safe-hook %lu failed (cannot find the service descriptor table base address)\n", SyscallNumber);
		return STATUS_NOT_FOUND;
	}
	KernelImageBaseAddress = memory_helpers::GetModuleBaseAddressADD("\\SystemRoot\\System32\\ntoskrnl.exe");

	if (KernelImageBaseAddress == NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver SSDT safe-hook %lu failed (cannot find the base address of the kernel image)\n", SyscallNumber);
		return STATUS_NOT_FOUND;
	}
	if (KernelTextSection == NULL || TextSectionSize == 0) {
		KernelTextSection = (BYTE*)memory_helpers::GetTextSectionOfSystemModuleADD(KernelImageBaseAddress, &TextSectionSize);
	}
	if (KernelTextSection == NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver SSDT safe-hook %lu failed (cannot find the base address of the .text section of the kernel)\n", SyscallNumber);
		return STATUS_NOT_FOUND;
	}


	// Get the address of the original function from the SSDT and copy the new function (HookingFunction) to the trampoline hook:
	switch (Tag) {
	case NTLOADDRIVER_TAG:
		OriginalFunction = &NtLoadDriverActual; SyscallNumber = NTLOADDRIVER_SYSCALL1809; break;
	default:
		DbgPrintEx(0, 0, "ProtectionDriver SSDT safe-hook failed (invalid tag: %lu)\n", Tag);
		return STATUS_INVALID_PARAMETER;
	}
	*OriginalFunction = (PVOID)SSDT::CurrentSSDTFuncAddr(SyscallNumber);
	RtlCopyMemory(&DummyTrampoline[3], &HookingFunction, sizeof(PVOID));


	// Find a long enough sequence of nop/int3 instructions in the kernel's .text section to put the trampoline hook in:
	TrampolineSection = memory_helpers::FindUnusedMemoryADD((BYTE*)KernelTextSection, TextSectionSize, sizeof(DummyTrampoline));
	if (TrampolineSection == NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver SSDT safe-hook %lu failed (cannot find sequence of %zu bytes that are nop/int3 instructions, %p, %lu)\n", SyscallNumber, sizeof(DummyTrampoline), KernelTextSection, TextSectionSize);
		return STATUS_NOT_FOUND;
	}


	// Map the kernel into writeable space to be able to put trampoline hook in and modify the SSDT entry:
	KernelModuleDescriptor = IoAllocateMdl(TrampolineSection, sizeof(DummyTrampoline), 0, 0, NULL);
	if (KernelModuleDescriptor == NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver SSDT safe-hook %lu failed (cannot allocate module descriptor to write into the kernel image, %p, %zu)\n", SyscallNumber, TrampolineSection, sizeof(DummyTrampoline));
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	MmProbeAndLockPages(KernelModuleDescriptor, KernelMode, IoWriteAccess);
	KernelMapping = MmMapLockedPagesSpecifyCache(KernelModuleDescriptor, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
	if (KernelMapping == NULL) {
		MmUnlockPages(KernelModuleDescriptor);
		IoFreeMdl(KernelModuleDescriptor);
		DbgPrintEx(0, 0, "ProtectionDriver SSDT safe-hook %lu failed (cannot map the kernel into writeable memory)\n", SyscallNumber);
		return STATUS_UNSUCCESSFUL;
	}


	// Patch the SSDT entry and write trampoline hook into the kernel:
	ServiceTableBase = (PULONG)KiServiceDescriptorTable->ServiceTableBase;
	CurrentIRQL = SSDT::DisableWriteProtection();  // Disable WP (Write-Protection) to be able to write into the SSDT
	RtlCopyMemory(KernelMapping, DummyTrampoline, sizeof(DummyTrampoline));  // Copy the trampoline hook in the kernel's memory
	SSDTEntryValue = SSDT::GetOffsetFromSSDTBase((ULONG64)TrampolineSection);
	SSDTEntryValue = SSDTEntryValue & 0xFFFFFFF0;
	SSDTEntryValue += ServiceTableBase[SyscallNumber] & 0x0F;
	ServiceTableBase[SyscallNumber] = SSDTEntryValue;
	SSDT::EnableWriteProtection(CurrentIRQL);  // Enable WP (Write-Protection) to restore earlier settings


	// Unmap the kernel image:
	MmUnmapLockedPages(KernelMapping, KernelModuleDescriptor);
	MmUnlockPages(KernelModuleDescriptor);
	IoFreeMdl(KernelModuleDescriptor);
	DbgPrintEx(0, 0, "ProtectionDriver SSDT safe-hook %lu succeeded\n", SyscallNumber);
	return STATUS_SUCCESS;
}


// Not related to SSDT but to driver protection
NTSTATUS UnhookNtLoadDriver() {
	if (NtLoadDriverActual == NULL) {
		return STATUS_SUCCESS;  // NtLoadDriver() was not hooked yet
	}
	return SSDT::SystemServiceDTUnhook(NtLoadDriverActual, NTLOADDRIVER_SYSCALL1809);
}


NTSTATUS NtLoadDriverProtection(IN PUNICODE_STRING DriverRegistryPath) {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	WCHAR SystemRootPrefix[] = L"\\SystemRoot\\";
	WCHAR SystemRootReplace[] = L"\\DosDevices\\C:\\Windows\\";
	WCHAR System32Prefix[] = L"System32\\";
	WCHAR System32Prepend[] = L"\\DosDevices\\C:\\Windows\\";
	WCHAR FilePath[MAX_PATH] = { 0 };

	RTL_QUERY_REGISTRY_TABLE DriverKeyQueriedValues[2] = { 0 };
	WCHAR KeyValue[MAX_PATH] = { 0 };

	HANDLE DriverFileHandle = NULL;
	UNICODE_STRING FileNameUnicode = { 0 };
	IO_STATUS_BLOCK DriverStatusBlock = { 0 };
	OBJECT_ATTRIBUTES DriverObjectAttrs = { 0 };
	FILE_STANDARD_INFORMATION DriverFileInfo = { 0 };
	LARGE_INTEGER DriverFileSize = { 0 };
	PVOID DriverDataPool = NULL;
	PVOID HashedDriverDataPool = NULL;
	ULONG HashedDriverDataLength = 0;
	LoadDriver ActualNtLoadDriver = NULL;


	// Initialize requested values/subkeys list for RtlQueryRegistryValues + mark end of table:
	DriverKeyQueriedValues[0].Name = L"ImagePath";
	DriverKeyQueriedValues[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_TYPECHECK;
	DriverKeyQueriedValues[0].EntryContext = KeyValue;
	DriverKeyQueriedValues[1].Name = NULL;
	DriverKeyQueriedValues[1].QueryRoutine = NULL;
	if (!NT_SUCCESS(RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, DriverRegistryPath->Buffer, DriverKeyQueriedValues, NULL, NULL))) {
		goto CallActual;
	}
	FileNameUnicode.Buffer = KeyValue;
	FileNameUnicode.Length = (USHORT)(wcslen(KeyValue) * sizeof(WCHAR));
	FileNameUnicode.MaximumLength = (USHORT)((wcslen(KeyValue) + 1) * sizeof(WCHAR));
	DbgPrintEx(0, 0, "ProtectionDriver NtLoadDriver() log - Raw ImagePath specified in registry key is %wZ\n", &FileNameUnicode);


	// Known instances - straight paths, starts with "System32\\...", starts with "\\SystemRoot\\":
	if (RtlCompareMemory(KeyValue, SystemRootPrefix, wcslen(SystemRootPrefix) * sizeof(WCHAR)) == wcslen(SystemRootPrefix) * sizeof(WCHAR)) {
		wcscat_s(FilePath, SystemRootReplace);
		wcscat_s(FilePath, (WCHAR*)((ULONG64)KeyValue + (wcslen(SystemRootPrefix) * sizeof(WCHAR))));
	}
	else if (RtlCompareMemory(KeyValue, System32Prefix, wcslen(System32Prefix) * sizeof(WCHAR)) == wcslen(System32Prefix) * sizeof(WCHAR)) {
		wcscat_s(FilePath, System32Prepend);
		wcscat_s(FilePath, KeyValue);
	}
	else {
		wcscat_s(FilePath, KeyValue);
	}
	FileNameUnicode.Buffer = FilePath;
	FileNameUnicode.Length = (USHORT)(wcslen(FilePath) * sizeof(WCHAR));
	FileNameUnicode.MaximumLength = (USHORT)((wcslen(FilePath) + 1) * sizeof(WCHAR));
	DbgPrintEx(0, 0, "ProtectionDriver NtLoadDriver() log - Fixed/Resolved ImagePath specified in registry key is %wZ\n", &FileNameUnicode);


	// Open handle to driver file (and verify existence):
	InitializeObjectAttributes(&DriverObjectAttrs, &FileNameUnicode, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	if (!NT_SUCCESS(NtCreateFile(&DriverFileHandle, GENERIC_READ | SYNCHRONIZE, &DriverObjectAttrs, &DriverStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0))) {
		ObDereferenceObject(&DriverObjectAttrs);
		DbgPrintEx(0, 0, "ProtectionDriver NtLoadDriver() log - Failed to create handle for driver file %wZ\n", &FileNameUnicode);
		goto CallActual;
	}


	// Get driver file size and allocate memory for driver data:
	if (!NT_SUCCESS(ZwQueryInformationFile(DriverFileHandle, &DriverStatusBlock, &DriverFileInfo,
		sizeof(DriverFileInfo), FileStandardInformation))) {
		NtClose(DriverFileHandle);
		ObDereferenceObject(&DriverObjectAttrs);
		DbgPrintEx(0, 0, "ProtectionDriver NtLoadDriver() log - Failed to get size of driver file %wZ\n", &FileNameUnicode);
		goto CallActual;
	}
	DriverFileSize = DriverFileInfo.EndOfFile;
	DriverDataPool = ExAllocatePoolWithTag(NonPagedPool, DriverFileSize.QuadPart, 'NlDs');
	if (DriverDataPool == NULL) {
		NtClose(DriverFileHandle);
		ObDereferenceObject(&DriverObjectAttrs);
		DbgPrintEx(0, 0, "ProtectionDriver NtLoadDriver() log - Failed to allocate memory for data of driver file %wZ\n", &FileNameUnicode);
		goto CallActual;
	}

	// Read driver file data into the pool:
	if (!NT_SUCCESS(NtReadFile(DriverFileHandle, NULL, NULL, NULL, &DriverStatusBlock, DriverDataPool,
		(ULONG)DriverFileSize.QuadPart, 0, NULL))) {
		NtClose(DriverFileHandle);
		ExFreePool(DriverDataPool);
		ObDereferenceObject(&DriverObjectAttrs);
		DbgPrintEx(0, 0, "ProtectionDriver NtLoadDriver() log - Failed to read data of driver file %wZ to memory pool\n", &FileNameUnicode);
		goto CallActual;
	}


	// Get the SHA256 hash of the driver data:
	Status = general_helpers::CreateDataHashADD(DriverDataPool, (ULONG)DriverFileSize.QuadPart,
		BCRYPT_SHA256_ALGORITHM, &HashedDriverDataPool, &HashedDriverDataLength);
	if (!NT_SUCCESS(Status) || HashedDriverDataLength == 0 || HashedDriverDataPool == NULL) {
		NtClose(DriverFileHandle);
		ExFreePool(DriverDataPool);
		ObDereferenceObject(&DriverObjectAttrs);
		DbgPrintEx(0, 0, "ProtectionDriver NtLoadDriver() log - Failed to create SHA256 hash of driver file %wZ, status: 0x%x\n", &FileNameUnicode, Status);
		goto CallActual;
	}


	// Compare the driver's SHA256 hash to the vulnurable list:
	for (ULONG VulnHashIndex = 0; VulnHashIndex < VULNLIST_SIZE; VulnHashIndex++) {
		if (RtlCompareMemory(VulnurableByteList[VulnHashIndex], HashedDriverDataPool, SHA256_HASHSIZE) == SHA256_HASHSIZE) {
			NtClose(DriverFileHandle);
			ExFreePool(DriverDataPool);
			ExFreePool(HashedDriverDataPool);
			ObDereferenceObject(&DriverObjectAttrs);
			DbgPrintEx(0, 0, "ProtectionDriver NtLoadDriver() log - Found vulnurable SHA256 hash of driver file %wZ at index %lu in list, terminating ...\n", &FileNameUnicode, VulnHashIndex);
			return STATUS_UNSUCCESSFUL;  // Current driver is vulnurable, fail the loading process of the driver
		}
	}


	// Free remaining data:
	NtClose(DriverFileHandle);
	ExFreePool(DriverDataPool);
	ExFreePool(HashedDriverDataPool);
	ObDereferenceObject(&DriverObjectAttrs);

CallActual:
	if (ActualNtLoadDriver == NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver NtLoadDriver() log - Original address of NtLoadDriver() = NULL\n");
		return STATUS_UNSUCCESSFUL;
	}
	ActualNtLoadDriver = (LoadDriver)ActualNtLoadDriver;
	return ActualNtLoadDriver(DriverRegistryPath);
}