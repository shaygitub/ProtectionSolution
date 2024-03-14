#include "IrpProtect.h"
#pragma warning(disable : 4996)


// Global variables (protected functions):
IRP_PROTECT NsiProxyProtect = { 0 };
IRP_PROTECT TcpIpProtect = { 0 };


NTSTATUS InitializeIrpProtection(LPCWSTR DriverName, LPCSTR DriverFileName, PIRP_PROTECT ProtectedData) {
	// Note: DriverName is expected to be in the format of: L"\\Driver\\DriverName"

	OBJECT_ATTRIBUTES DriverAttr = { 0 };
	IO_STATUS_BLOCK DriverStatus = { 0 };
	HANDLE DriverHandle = NULL;
	PSYSTEM_MODULE DriverSystemModule = NULL;
	LPCSTR DriverSymbolicLink = NULL;
	LPCSTR DriverFilePrefix = "\\SystemRoot\\System32\\";
	RtlInitUnicodeString(&ProtectedData->DriverName, DriverName);
	InitializeObjectAttributes(&DriverAttr, &ProtectedData->DriverName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	
	// Get the DRIVER_OBJECT for the driver to protect:
	if (!NT_SUCCESS(ZwCreateFile(&DriverHandle, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, &DriverAttr, &DriverStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)) || DriverHandle == NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver IRP protection - Failed to get handle of driver %wZ\n", &ProtectedData->DriverName);
		RtlFreeUnicodeString(&ProtectedData->DriverName);
		return STATUS_UNSUCCESSFUL;
	}
	if (!NT_SUCCESS(ObReferenceObjectByHandle(DriverHandle, FILE_ALL_ACCESS, *IoFileObjectType, KernelMode, (PVOID*)&ProtectedData->DriverObject, NULL))) {
		DbgPrintEx(0, 0, "ProtectionDriver IRP protection - Failed to get DRIVER_OBJECT of driver %wZ\n", &ProtectedData->DriverName);
		RtlFreeUnicodeString(&ProtectedData->DriverName);
		return STATUS_UNSUCCESSFUL;
	}


	// Iterate through the existing IRP major functions and log them and their starting bytes:
	for (USHORT IrpMjIndex = 0; IrpMjIndex <= IRP_MJ_MAXIMUM_FUNCTION; IrpMjIndex++) {
		ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher = ProtectedData->DriverObject->MajorFunction[IrpMjIndex];
		RtlCopyMemory(ProtectedData->IrpDispatchers[IrpMjIndex].MajorFunctionData,
			ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher, IRPMAJOR_CHECKEDOFFSET);
	}


	// Log the base of the kernel module and size of the protected driver:
	DriverSymbolicLink = (LPCSTR)ExAllocatePoolWithTag(NonPagedPool, 
		strlen(DriverFilePrefix) + strlen(DriverFileName) + 1, 'DsLb');
	if (DriverSymbolicLink == NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver IRP protection - Failed to allocate memory for symbolic link of driver %wZ\n", &ProtectedData->DriverName);
		RtlFreeUnicodeString(&ProtectedData->DriverName);
		return STATUS_UNSUCCESSFUL;
	}
	RtlCopyMemory((PVOID)DriverSymbolicLink, DriverFilePrefix, strlen(DriverFilePrefix));
	RtlCopyMemory((PVOID)((ULONG64)DriverSymbolicLink + strlen(DriverFilePrefix)),
		DriverFileName, strlen(DriverFileName) + 1);
	DriverSystemModule = memory_helpers::GetModuleBaseAddressADD(DriverSymbolicLink);
	if (DriverSystemModule == NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver IRP protection - Failed to get PSYSTEM_MODULE for driver %wZ\n", &ProtectedData->DriverName);
		RtlFreeUnicodeString(&ProtectedData->DriverName);
		ExFreePool((PVOID)DriverSymbolicLink);
		return STATUS_UNSUCCESSFUL;
	}
	ExFreePool((PVOID)DriverSymbolicLink);


	// Check if any of the addresses are out of bounds for the protected driver:
	ProtectedData->DriverImageBase = DriverSystemModule->Base;
	ProtectedData->DriverImageSize = (ULONG64)DriverSystemModule->Size;
	for (USHORT IrpMjIndex = 0; IrpMjIndex <= IRP_MJ_MAXIMUM_FUNCTION; IrpMjIndex++) {
		ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher = ProtectedData->DriverObject->MajorFunction[IrpMjIndex];
		RtlCopyMemory(ProtectedData->IrpDispatchers[IrpMjIndex].MajorFunctionData,
			ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher, IRPMAJOR_CHECKEDOFFSET);
		if ((ULONG64)(ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher) < (ULONG64)ProtectedData->DriverImageBase ||
			(ULONG64)(ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher) > (ULONG64)ProtectedData->DriverImageBase + ProtectedData->DriverImageSize) {
			DbgPrintEx(0, 0, "ProtectionDriver IRP protection - Initial IRP major function %lu of driver %wZ is out of the module bounds\n", IrpMjIndex, &ProtectedData->DriverName);
			general_helpers::TriggerBlueScreenOfDeath();
			return STATUS_UNSUCCESSFUL;
		}
	}
	return STATUS_SUCCESS;
}


NTSTATUS IrpHookingProtection(PIRP_PROTECT ProtectedData) {
	OBJECT_ATTRIBUTES DriverAttr = { 0 };
	IO_STATUS_BLOCK DriverStatus = { 0 };
	HANDLE DriverHandle = NULL;
	PDRIVER_OBJECT CurrentDriverObject = NULL;


	// Get the current DRIVER_OBJECT to verify changes, if does not work - use the initially logged DRIVER_OBJECT:
	InitializeObjectAttributes(&DriverAttr, &ProtectedData->DriverName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	if (NT_SUCCESS(ZwCreateFile(&DriverHandle, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, &DriverAttr, &DriverStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)) || DriverHandle == NULL) {
		if (NT_SUCCESS(ObReferenceObjectByHandle(DriverHandle, FILE_ALL_ACCESS, *IoFileObjectType, KernelMode, (PVOID*)&CurrentDriverObject, NULL))) {
			if ((ULONG64)CurrentDriverObject != (ULONG64)ProtectedData->DriverObject) {
				DbgPrintEx(0, 0, "ProtectionDriver IRP protection - ObReferenceObjectByHandle was hooked / data was patched, returned DRIVER_OBJECT %p instead of %p\n", CurrentDriverObject, ProtectedData->DriverObject);
				general_helpers::TriggerBlueScreenOfDeath();
				return STATUS_UNSUCCESSFUL;
			}
		}
	}


	// Verify all major dispatch function pointers against the database:
	for (USHORT IrpMjIndex = 0; IrpMjIndex <= IRP_MJ_MAXIMUM_FUNCTION; IrpMjIndex++) {
		if (ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher !=
			ProtectedData->DriverObject->MajorFunction[IrpMjIndex]) {
			DbgPrintEx(0, 0, "ProtectionDriver IRP protection - Found IRP hook in major function %lu of driver %wZ, trying to fix\n", IrpMjIndex, &ProtectedData->DriverName);
			InterlockedExchange64((LONG64*)(&(ProtectedData->DriverObject->MajorFunction[IrpMjIndex])),
				(LONG64)ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher);
			if (ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher !=
				ProtectedData->DriverObject->MajorFunction[IrpMjIndex]) {
				DbgPrintEx(0, 0, "ProtectionDriver IRP protection - Failed to unhook the IRP major function %lu of driver %wZ\n", IrpMjIndex, &ProtectedData->DriverName);
				general_helpers::TriggerBlueScreenOfDeath();
				return STATUS_UNSUCCESSFUL;
			}
		}
	}
	return STATUS_SUCCESS;
}


NTSTATUS IrpInlineHookProtection(PIRP_PROTECT ProtectedData) {
	SIZE_T LastEqualByte = 0;
	for (USHORT IrpMjIndex = 0; IrpMjIndex <= IRP_MJ_MAXIMUM_FUNCTION; IrpMjIndex++) {
		LastEqualByte = RtlCompareMemory(ProtectedData->IrpDispatchers[IrpMjIndex].MajorFunctionData,
			ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher, IRPMAJOR_CHECKEDOFFSET);
		if (LastEqualByte != IRPMAJOR_CHECKEDOFFSET) {
			DbgPrintEx(0, 0, "ProtectionDriver IRP protection - Found IRP inline hook in major function %lu of driver %wZ, trying to fix\n", IrpMjIndex, &ProtectedData->DriverName);
			if (!memory_transfer::WriteToReadOnlyMemoryADD(ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher,
				ProtectedData->IrpDispatchers[IrpMjIndex].MajorFunctionData, IRPMAJOR_CHECKEDOFFSET, TRUE)) {
				DbgPrintEx(0, 0, "ProtectionDriver IRP protection - Failed to fix inline hook of the IRP major function %lu of driver %wZ\n", IrpMjIndex, &ProtectedData->DriverName);
				general_helpers::TriggerBlueScreenOfDeath();
				return STATUS_UNSUCCESSFUL;
			}
		}
	}
	return STATUS_SUCCESS;
}


PVOID IrpPatchProtection() {
	LARGE_INTEGER TimerNanoCount = { 0 };
	TimerNanoCount.QuadPart = 600000000;  // 600,000,000 units of 100 nano seconds = 60 seconds


	// Initialize the structs used to verify data for the saved drivers:
	if (!NT_SUCCESS(InitializeIrpProtection(L"\\Driver\\nsiproxy", "nsiproxy.sys", &NsiProxyProtect))) {
		goto Cleaning;
	}
	if (!NT_SUCCESS(InitializeIrpProtection(L"\\Driver\\tcpip", "tcpip.sys", &TcpIpProtect))) {
		goto Cleaning;
	}


	// Make an infinite loop to check for any manipulations:
	while (TRUE) {

		// IRP hooking protection:
		if (!NT_SUCCESS(IrpHookingProtection(&NsiProxyProtect)) ||
			!NT_SUCCESS(IrpHookingProtection(&TcpIpProtect))) {
			goto Cleaning;
		}


		// IRP inline hooking protection:
		if (!NT_SUCCESS(IrpInlineHookProtection(&NsiProxyProtect)) ||
			!NT_SUCCESS(IrpInlineHookProtection(&TcpIpProtect))) {
			goto Cleaning;
		}


		// Delay this thread's execution to mimic Sleep() for 5 seconds:
		if (!NT_SUCCESS(KeDelayExecutionThread(KernelMode, FALSE, &TimerNanoCount))) {
			DbgPrintEx(0, 0, "ProtectionDriver IRP protection - Failed to delay thread execution\n");
		}
	}

Cleaning:
	if (NsiProxyProtect.DriverName.Buffer != NULL && NsiProxyProtect.DriverName.Length != 0) {
		RtlFreeUnicodeString(&NsiProxyProtect.DriverName);
	}
	if (TcpIpProtect.DriverName.Buffer != NULL && TcpIpProtect.DriverName.Length != 0) {
		RtlFreeUnicodeString(&TcpIpProtect.DriverName);
	}
	return NULL;
}


BOOL FreeProtectedDrivers() {
	if (NsiProxyProtect.DriverName.Buffer != NULL && NsiProxyProtect.DriverName.Length != 0) {
		RtlFreeUnicodeString(&NsiProxyProtect.DriverName);
	}
	if (TcpIpProtect.DriverName.Buffer != NULL && TcpIpProtect.DriverName.Length != 0) {
		RtlFreeUnicodeString(&TcpIpProtect.DriverName);
	}
	return TRUE;
}