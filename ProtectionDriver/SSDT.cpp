#include "syscalls.h"
#include "SSDTGlobals.h"
#include "helpers.h"


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