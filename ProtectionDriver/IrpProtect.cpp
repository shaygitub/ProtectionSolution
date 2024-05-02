#include "IrpProtect.h"
#pragma warning(disable : 4996)


// Global variables (protected functions):
IRP_PROTECT NsiProxyProtect = { 0 };
IRP_PROTECT TcpIpProtect = { 0 };


NTSTATUS InitializeIrpProtection(ULONG DriverTag, LPCSTR DriverFileName, PIRP_PROTECT ProtectedData) {
	// Note: DriverName is expected to be in the format of: L"\\Driver\\DriverName"

	PDRIVER_OBJECT DriverObject = NULL;
	PSYSTEM_MODULE DriverSystemModule = NULL;
	char DriverModuleName1[MAX_PATH] = "\\SystemRoot\\system32\\drivers\\";
	char DriverModuleName2[MAX_PATH] = "\\SystemRoot\\System32\\drivers\\";


	// Get the name of the driver in a UNICODE_STRING format:
	switch (DriverTag) {
	case TCPIP_TAG:
		if (!NT_SUCCESS(unicode_helpers::InitiateUnicode(L"\\Driver\\tcpip", 'TdTb',
			&ProtectedData->DriverName)) || ProtectedData->DriverName.Buffer == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver IRP - Cannot initiate unicode string for \\Driver\\tcpip\n");
			ProtectedData->DriverName.Buffer = NULL;
			return STATUS_UNSUCCESSFUL;
		}
		break;

	case NSIPROXY_TAG:
		if (!NT_SUCCESS(unicode_helpers::InitiateUnicode(L"\\Driver\\nsiproxy", 'TdNb',
			&ProtectedData->DriverName)) || ProtectedData->DriverName.Buffer == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver IRP - Cannot initiate unicode string for \\Driver\\Nsiproxy\n");
			ProtectedData->DriverName.Buffer = NULL;
			return STATUS_UNSUCCESSFUL;
		}
		break;
	default:
		ProtectedData->DriverName.Buffer = NULL;
		return STATUS_INVALID_PARAMETER;
	}


	// Get the DRIVER_OBJECT for the driver to protect:
	DriverObject = general_helpers::GetDriverObjectADD(&ProtectedData->DriverName);
	if (DriverObject == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver IRP protection - Cannot initialize protection for driver %wZ, driver object cannot be resolved\n", &ProtectedData->DriverName);
		unicode_helpers::FreeUnicode(&ProtectedData->DriverName);
		ProtectedData->DriverName.Buffer = NULL;
		return STATUS_UNSUCCESSFUL;
	}

	
	// Iterate through the existing IRP major functions and log them and their starting bytes:
	for (USHORT IrpMjIndex = 0; IrpMjIndex <= IRP_MJ_MAXIMUM_FUNCTION; IrpMjIndex++) {
		ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher = ProtectedData->DriverObject->MajorFunction[IrpMjIndex];
		RtlCopyMemory(ProtectedData->IrpDispatchers[IrpMjIndex].MajorFunctionData,
			ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher, IRPMAJOR_CHECKEDOFFSET);
	}

	
	// Log the base of the kernel module and size of the protected driver:
	strcat_s(DriverModuleName1, DriverFileName);
	strcat_s(DriverModuleName2, DriverFileName);
	DriverSystemModule = (PSYSTEM_MODULE)memory_helpers::GetModuleBaseAddressADD(DriverModuleName1);
	if (DriverSystemModule == NULL) {
		DbgPrintEx(0, 0, "ProtectionDriver IRP protection - Failed to get PSYSTEM_MODULE for driver %wZ with first pattern\n", &ProtectedData->DriverName);
		DriverSystemModule = (PSYSTEM_MODULE)memory_helpers::GetModuleBaseAddressADD(DriverModuleName2);
		if (DriverSystemModule == NULL) {
			DbgPrintEx(0, 0, "ProtectionDriver IRP protection - Failed to get PSYSTEM_MODULE for driver %wZ with second pattern\n", &ProtectedData->DriverName);
			ProtectedData->DriverName.Buffer = NULL;
			return STATUS_UNSUCCESSFUL;
		}
	}


	// Check if any of the addresses are out of bounds for the protected driver:
	ProtectedData->DriverImageBase = DriverSystemModule->Base;
	ProtectedData->DriverImageSize = (ULONG64)DriverSystemModule->Size;
	for (USHORT IrpMjIndex = 0; IrpMjIndex <= IRP_MJ_MAXIMUM_FUNCTION; IrpMjIndex++) {
		ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher = 
			ProtectedData->DriverObject->MajorFunction[IrpMjIndex];
		RtlCopyMemory(ProtectedData->IrpDispatchers[IrpMjIndex].MajorFunctionData,
			ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher, IRPMAJOR_CHECKEDOFFSET);
		if ((ULONG64)(ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher) < (ULONG64)ProtectedData->DriverImageBase ||
			(ULONG64)(ProtectedData->IrpDispatchers[IrpMjIndex].IrpDispatcher) > (ULONG64)ProtectedData->DriverImageBase + ProtectedData->DriverImageSize) {
			DbgPrintEx(0, 0, "ProtectionDriver IRP protection - Initial IRP major function %lu of driver %wZ is out of the module bounds\n", IrpMjIndex, &ProtectedData->DriverName);
			protection_helpers::TriggerBlueScreenOfDeath();
			ProtectedData->DriverName.Buffer = NULL;
			return STATUS_UNSUCCESSFUL;
		}
	}
	return STATUS_SUCCESS;
}


NTSTATUS IrpHookingProtection(PIRP_PROTECT ProtectedData) {
	PDRIVER_OBJECT CurrentDriverObject = NULL;


	// Get the current DRIVER_OBJECT to verify changes, if does not work - use the initially logged DRIVER_OBJECT:
	CurrentDriverObject = general_helpers::GetDriverObjectADD(&ProtectedData->DriverName);
	if (CurrentDriverObject != NULL) {
		if ((ULONG64)CurrentDriverObject != (ULONG64)ProtectedData->DriverObject) {
			DbgPrintEx(0, 0, "ProtectionDriver IRP protection - ObReferenceObjectByHandle was hooked / data was patched, returned DRIVER_OBJECT %p instead of %p\n", CurrentDriverObject, ProtectedData->DriverObject);
			protection_helpers::TriggerBlueScreenOfDeath();
			return STATUS_UNSUCCESSFUL;
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
				protection_helpers::TriggerBlueScreenOfDeath();
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
				protection_helpers::TriggerBlueScreenOfDeath();
				return STATUS_UNSUCCESSFUL;
			}
		}
	}
	return STATUS_SUCCESS;
}


PVOID IrpPatchProtection(THREAD_STATUS* IrpThreadStop) {
	LARGE_INTEGER TimerNanoCount = { 0 };
	TimerNanoCount.QuadPart = 600000000;  // 600,000,000 units of 100 nano seconds = 60 seconds


	// Initialize the structs used to verify data for the saved drivers:
	if (!NT_SUCCESS(InitializeIrpProtection(NSIPROXY_TAG, "nsiproxy.sys", &NsiProxyProtect))) {
		goto Cleaning;
	}
	if (!NT_SUCCESS(InitializeIrpProtection(TCPIP_TAG, "tcpip.sys", &TcpIpProtect))) {
		goto Cleaning;
	}


	// Make an infinite loop to check for any manipulations:
	while (*IrpThreadStop != TerminateStatus) {

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
	/*
	if (NsiProxyProtect.DriverName.Buffer != NULL && NsiProxyProtect.DriverName.Length != 0) {
		unicode_helpers::FreeUnicode(&NsiProxyProtect.DriverName);
	}
	if (TcpIpProtect.DriverName.Buffer != NULL && TcpIpProtect.DriverName.Length != 0) {
		unicode_helpers::FreeUnicode(&TcpIpProtect.DriverName);
	}
	*/
	DbgPrintEx(0, 0, "ProtectionDriver - IrpPatchProtection() terminated\n");
	*IrpThreadStop = FinishedStatus;
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