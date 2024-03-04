#pragma once
#include "definitions.h"


namespace general_helpers {
	NTSTATUS OpenProcessHandleADD(HANDLE* Process, ULONG64 PID);  // Get process handle with PID of the process
	NTSTATUS CopyStringAfterCharADD(PUNICODE_STRING OgString, PUNICODE_STRING NewString, WCHAR Char);  // Copy substring after last apearance of defined character
	BOOL CompareUnicodeStringsADD(PUNICODE_STRING First, PUNICODE_STRING Second, USHORT CheckLength);  // Compare two unicode strings
	BOOL IsExistFromIndexADD(PUNICODE_STRING Inner, PUNICODE_STRING Outer, USHORT StartIndex);  // Find inner in outer from start index
	void PrintUnicodeStringADD(PUNICODE_STRING Str);  // Print a UNICODE_STRING letter-by-letter
	NTSTATUS GetPidNameFromListADD(ULONG64* ProcessId, char ProcessName[15], BOOL NameGiven);  // Get the PID of a process from its name
	ULONG GetActualLengthADD(PUNICODE_STRING String);  // Get the actual length of the string
	void ExecuteInstructionsADD(BYTE Instructions[], SIZE_T InstructionsSize);  // Execute the instructions given
	NTSTATUS CreateDataHashADD(PVOID DataToHash, ULONG SizeOfDataToHash, LPCWSTR HashName, 
		PVOID* HashedDataOutput, ULONG* HashedDataLength);  // Create hash digestion of the provided data
}

namespace memory_helpers {
	BOOL FreeAllocatedMemoryADD(PEPROCESS EpDst, ULONG OldState, PVOID BufferAddress, SIZE_T BufferSize);  // frees memory that was allocated during writing/by CommitMemoryRegionsADD
	PVOID AllocateMemoryADD(PVOID InitialAddress, SIZE_T AllocSize, KAPC_STATE* CurrState, ULONG_PTR ZeroBits);  // allocate memory by parameters (assumes: already attached)
	ULONG64 GetHighestUserModeAddrADD();  // retrieves the maximum usermode address for the local machine
	PVOID FindUnusedMemoryADD(BYTE* SearchSection, ULONG SectionSize, SIZE_T NeededLength);  // Find a section of code with enough empty instuctions to fit a NeededLength sized data in it
	PVOID GetModuleBaseAddressADD(const char* ModuleName);  // Get the base address of a system module/ntoskrnl.exe
	PVOID GetTextSectionOfSystemModuleADD(PVOID ModuleBaseAddress, ULONG* TextSectionSize);  // Get the address of the code (.text) section of a system module
	PIMAGE_SECTION_HEADER GetSectionHeaderFromNameADD(PVOID ModuleBaseAddress, const char* SectionName);  // Get the section by the name from a system module
	BOOL ChangeProtectionSettingsADD(HANDLE ProcessHandle, PVOID Address, ULONG Size, ULONG ProtSettings, ULONG OldProtect);
	PVOID CommitMemoryRegionsADD(HANDLE ProcessHandle, PVOID Address, SIZE_T Size, ULONG AllocProt, PVOID ExistingAllocAddr, ULONG_PTR ZeroBit);
	ULONG MatchPatternADD(const BYTE CompareTo[], BYTE ComparingData[], const char* CompareMask, ULONG64 CompareSize);  // Compare ComparingData to CompareTo, x = compare, ? = don't compare
}


namespace memory_transfer {
	BOOL WriteMemoryADD(PVOID WriteAddress, PVOID SourceBuffer, SIZE_T WriteSize);  // Wrapper function to RtlCopyMemory in KM
	BOOL WriteToReadOnlyMemoryADD(PVOID Address, PVOID Buffer, SIZE_T Size, BOOL IsWrite);  // Write to read-only memory using descriptor modules
	NTSTATUS UserToKernelADD(PEPROCESS SrcProcess, PVOID UserAddress, PVOID KernelAddress, SIZE_T Size, BOOL IsAttached);  // UM -> KM
	NTSTATUS KernelToUserADD(PEPROCESS DstProcess, PVOID KernelAddress, PVOID UserAddress, SIZE_T Size, BOOL IsAttached);  // KM -> UM
}