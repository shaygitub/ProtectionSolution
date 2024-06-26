#pragma once
#include "definitions.h"
#define TRACED_SYSTEM_MODULES 1000

namespace SSDT {
	NTSTATUS InitializeSSDTParameters();  // Initialize SSDT parameters
	ULONG GetSystemCallIndex(PUNICODE_STRING SystemServiceName);  // Get the index of a system service in the SSDT with its name
	KIRQL DisableWriteProtection();   // Disable write protection to be able to write (like in an SSDT hook)
	void EnableWriteProtection(KIRQL CurrentIRQL);  // Enable write protection like normal. IRQL provided for operation
	ULONG64 CurrentSSDTFuncAddr(ULONG SyscallNumber);  // Get the address of the current function signed as the system service at syscall number SyscallNumber
	ULONG64 GetServiceDescriptorTable();  // Get the base address of the actual SSDT in memory
	ULONG GetOffsetFromSSDTBase(ULONG64 FunctionAddress);  // Get the offset of a function/address from the base of the SSDT table (used to calculate entry value)
	NTSTATUS SystemServiceDTUnhook(ULONG Tag, PVOID* OriginalFunction);  // Unhook the SSDT entry
	NTSTATUS SystemServiceDTHook(PVOID HookingFunction, ULONG Tag);  // Safe-hook the SSDT entry
}
NTSTATUS InitializeSyscallProtectedFunction(LPCWSTR FunctionName, ULONG64 FullInstructionSize,
	PSYSCALL_PROTECT ProtectedData, ULONG SyscallNumber, ULONG SyscallTag);
BOOL FreeProtectedFunctions();
NTSTATUS SSDTHookProtection(PSYSCALL_PROTECT ProtectedFunction);
NTSTATUS SSInlineHookProtection(PSYSCALL_PROTECT ProtectedFunction);
PVOID SystemCallsProtection(THREAD_STATUS* SyscallThreadStop);