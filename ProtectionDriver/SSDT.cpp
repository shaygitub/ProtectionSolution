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


NTSTATUS SSDT::SystemServiceDTUnhook(ULONG Tag, PVOID* OriginalFunction) {
	KIRQL CurrentIRQL = NULL;
	ULONG SSDTEntryValue = NULL;
	PVOID* ActualFunction = NULL;
	ULONG SyscallNumber = 0;
	PULONG KiServiceTableBase = NULL;

	if (Tag == 0 || (OriginalFunction == NULL && Tag != NTLOADDRIVER_TAG && Tag != NTDVCIOCNTRL_TAG)) {
		DbgPrintEx(0, 0, "ProtectionDriver SSDT unhook failed (invalid parameters: %lu, %p)\n", Tag, OriginalFunction);
		return STATUS_INVALID_PARAMETER;
	}
	switch (Tag) {
	case NTCREATEFILE_TAG: ActualFunction = OriginalFunction; SyscallNumber = NTCREATEFILE_SYSCALL; break;
	case NTQUERYSYSINFO_TAG: ActualFunction = OriginalFunction; SyscallNumber = NTQUERYSYSINFO_SYSCALL; break;
	case NTQUERYEX_TAG: ActualFunction = OriginalFunction; SyscallNumber = NTQUERYEX_SYSCALL; break;
	case NTQUERY_TAG: ActualFunction = OriginalFunction; SyscallNumber = NTQUERY_SYSCALL; break;
	case NTLOADDRIVER_TAG: ActualFunction = &NtLoadDriverActual; SyscallNumber = NTLOADDRIVER_SYSCALL; break;
	case NTDVCIOCNTRL_TAG: ActualFunction = &NtDeviceIoControlFileActual; SyscallNumber = NTDVCIOCNTRL_SYSCALL; break;
	default:
		DbgPrintEx(0, 0, "ProtectionDriver SSDT unhook failed (invalid tag: %lu)\n", Tag);
		return STATUS_INVALID_PARAMETER;
	}
	if (*ActualFunction == NULL) {
		return STATUS_SUCCESS;  // Syscall was not hooked, "success" in unhooking
	}


	// Unhook the SSDT entry to point to the initial address of the system service:
	KiServiceTableBase = (PULONG)KiServiceDescriptorTable->ServiceTableBase;
	CurrentIRQL = SSDT::DisableWriteProtection();
	SSDTEntryValue = SSDT::GetOffsetFromSSDTBase((ULONG64)*ActualFunction);
	SSDTEntryValue &= 0xFFFFFFF0;
	SSDTEntryValue += KiServiceTableBase[SyscallNumber] & 0x0F;
	KiServiceTableBase[SyscallNumber] = SSDTEntryValue;
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
	PVOID* OriginalFunction = NULL;
	PMDL KernelModuleDescriptor = NULL;
	KIRQL CurrentIRQL = NULL;
	ULONG SyscallNumber = 0;
	ULONG SSDTEntryValue = 0;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PULONG KiServiceTableBase = NULL;


	// Check for invalid parameters:
	if (HookingFunction == NULL || Tag == 0) {
		DbgPrintEx(0, 0, "ProtectionDriver SSDT safe-hook failed (invalid parameters: %p, %lu)\n", HookingFunction, Tag);
		return STATUS_INVALID_PARAMETER;
	}


	// Get the original function matching buffer and find the syscall number:
	switch (Tag) {
	case NTDVCIOCNTRL_TAG: OriginalFunction = &NtDeviceIoControlFileActual; SyscallNumber = NTDVCIOCNTRL_SYSCALL; break;
	case NTLOADDRIVER_TAG: OriginalFunction = &NtLoadDriverActual; SyscallNumber = NTLOADDRIVER_SYSCALL; break;
	default:
		DbgPrintEx(0, 0, "ProtectionDriver SSDT safe-hook failed (invalid tag: %lu)\n", Tag);
		return STATUS_INVALID_PARAMETER;
	}


	// Get the address of the original function from the SSDT and copy the new function (HookingFunction) to the trampoline hook:
	*OriginalFunction = (PVOID)SSDT::CurrentSSDTFuncAddr(SyscallNumber);
	RtlCopyMemory(&DummyTrampoline[3], &HookingFunction, sizeof(PVOID));
	DbgPrintEx(0, 0, "ProtectionDriver SSDT safe-hook, actual syscall function (%lu) - %p\n", SyscallNumber, *OriginalFunction);


	// Find a long enough sequence of nop/int3 instructions in the kernel's .text section to put the trampoline hook in:
	TrampolineSection = memory_helpers::FindUnusedMemoryADD((BYTE*)KernelTextSection, TextSectionSize, sizeof(DummyTrampoline));
	if (TrampolineSection == NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver SSDT safe-hook %lu failed (cannot find sequence of %zu bytes that are nop/int3 instructions, %p, %lu)\n", SyscallNumber, sizeof(DummyTrampoline), KernelTextSection, TextSectionSize);
		*OriginalFunction = NULL;
		return STATUS_NOT_FOUND;
	}
	DbgPrintEx(0, 0, "ProtectionDriver SSDT safe-hook, found code cave at %p (%lu)\n", TrampolineSection, SyscallNumber);

	
	// Map the kernel into writeable space to be able to put trampoline hook in and modify the SSDT entry:
	KernelModuleDescriptor = IoAllocateMdl(TrampolineSection, sizeof(DummyTrampoline), 0, 0, NULL);
	if (KernelModuleDescriptor == NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver SSDT safe-hook %lu failed (cannot allocate module descriptor to write into the kernel image, %p, %zu)\n", SyscallNumber, TrampolineSection, sizeof(DummyTrampoline));
		*OriginalFunction = NULL;
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	MmProbeAndLockPages(KernelModuleDescriptor, KernelMode, IoReadAccess);
	DbgPrintEx(0, 0, "ProtectionDriver SSDT hook, locked pages (%lu)\n", SyscallNumber);
	KernelMapping = MmMapLockedPagesSpecifyCache(KernelModuleDescriptor, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
	if (KernelMapping == NULL) {
		MmUnlockPages(KernelModuleDescriptor);
		IoFreeMdl(KernelModuleDescriptor);
		DbgPrintEx(0, 0, "ProtectionDriver SSDT safe-hook %lu failed (cannot map the kernel into writeable memory)\n", SyscallNumber);
		*OriginalFunction = NULL;
		return STATUS_UNSUCCESSFUL;
	}
	DbgPrintEx(0, 0, "ProtectionDriver SSDT hook, mapped module to %p (%lu)\n", KernelMapping, SyscallNumber);


	// Set the protection settings of the memory range to be both writeable and readable:
	Status = MmProtectMdlSystemAddress(KernelModuleDescriptor, PAGE_READWRITE);
	if (!NT_SUCCESS(Status)) {
		MmUnmapLockedPages(KernelMapping, KernelModuleDescriptor);
		MmUnlockPages(KernelModuleDescriptor);
		IoFreeMdl(KernelModuleDescriptor);
		DbgPrintEx(0, 0, "ProtectionDriver SSDT hook %lu failed (cannot change protection settings to RW)\n", SyscallNumber);
		*OriginalFunction = NULL;
		return STATUS_UNSUCCESSFUL;
	}


	// Patch the SSDT entry and write trampoline hook into the kernel:
	KiServiceTableBase = (PULONG)KiServiceDescriptorTable->ServiceTableBase;
	CurrentIRQL = SSDT::DisableWriteProtection();  // Disable WP (Write-Protection) to be able to write into the SSDT
	RtlCopyMemory(KernelMapping, DummyTrampoline, sizeof(DummyTrampoline));  // Copy the trampoline hook in the kernel's memory
	SSDTEntryValue = SSDT::GetOffsetFromSSDTBase((ULONG64)TrampolineSection);
	SSDTEntryValue &= 0xFFFFFFF0;
	SSDTEntryValue += KiServiceTableBase[SyscallNumber] & 0x0F;
	KiServiceTableBase[SyscallNumber] = SSDTEntryValue;
	SSDT::EnableWriteProtection(CurrentIRQL);  // Enable WP (Write-Protection) to restore earlier settings


	// Unmap the kernel image:
	MmUnmapLockedPages(KernelMapping, KernelModuleDescriptor);
	MmUnlockPages(KernelModuleDescriptor);
	IoFreeMdl(KernelModuleDescriptor);


	// Make sure the hook worked:
	if ((ULONG64)*OriginalFunction == SSDT::CurrentSSDTFuncAddr(SyscallNumber)) {
		DbgPrintEx(0, 0, "ProtectionDriver SSDT hook %lu failed, original function = entry value = %p\n", SyscallNumber, *OriginalFunction);
		*OriginalFunction = NULL;
		return STATUS_UNSUCCESSFUL;
	}
	DbgPrintEx(0, 0, "KMDFdriver SSDT hook %lu succeeded, original = %p, current entry = %p\n",
		SyscallNumber, *OriginalFunction, (PVOID)SSDT::CurrentSSDTFuncAddr(SyscallNumber));
	return STATUS_SUCCESS;
}


NTSTATUS SSDT::InitializeSSDTParameters() {

	// Make preperations for SSDT hook - get SSDT address, get ntoskrnl.exe image base and get .text section:
	KiServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)SSDT::GetServiceDescriptorTable();
	if (KiServiceDescriptorTable == NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver hook failed (cannot find the service descriptor table)\n");
		return STATUS_NOT_FOUND;
	}
	KernelImageBaseAddress = memory_helpers::GetModuleBaseAddressADD("\\SystemRoot\\System32\\ntoskrnl.exe");
	if (KernelImageBaseAddress == NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver SSDT failed (cannot find the base address of the kernel image)\n");
		return STATUS_NOT_FOUND;
	}
	DbgPrintEx(0, 0, "\n\nKernel base address: %p\n\n", KernelImageBaseAddress);

	KernelTextSection = (BYTE*)memory_helpers::GetTextSectionOfSystemModuleADD(KernelImageBaseAddress, &TextSectionSize);
	if (KernelTextSection == NULL || TextSectionSize == 0) {
		DbgPrintEx(0, 0, "ProtectionDriver SSDT failed (cannot find the base address / size of the .text section of the kernel)\n");
		return STATUS_NOT_FOUND;
	}
	DbgPrintEx(0, 0, "\n\nKernel .text section base address: %p\n\n", KernelTextSection);
	return STATUS_SUCCESS;
}