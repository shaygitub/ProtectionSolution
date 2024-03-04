#pragma once
#include <ntifs.h>
#include <wdm.h>
#include <minwindef.h>


// SSDT Hook global variables and definitions:
typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID ServiceTableBase;
	PVOID ServiceCounterTableBase;
	ULONG64 NumberOfServices;
	PVOID ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;

PSYSTEM_SERVICE_TABLE KiServiceDescriptorTable = NULL;
PVOID NtLoadDriverActual = NULL;