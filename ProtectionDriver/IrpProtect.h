#pragma once
#include "helpers.h"


NTSTATUS InitializeIrpProtection(ULONG DriverTag, LPCSTR DriverFileName, PIRP_PROTECT ProtectedData);
NTSTATUS IrpHookingProtection(PIRP_PROTECT ProtectedData);
NTSTATUS IrpInlineHookProtection(PIRP_PROTECT ProtectedData);
PVOID IrpPatchProtection(THREAD_STATUS* IrpThreadStop);
BOOL FreeProtectedDrivers();