#pragma once
#include "helpers.h"


NTSTATUS InitializeIrpProtection(LPCWSTR DriverName, LPCSTR DriverFileName, PIRP_PROTECT ProtectedData);
NTSTATUS IrpHookingProtection(PIRP_PROTECT ProtectedData);
NTSTATUS IrpInlineHookProtection(PIRP_PROTECT ProtectedData);
PVOID IrpPatchProtection();
BOOL FreeProtectedDrivers();