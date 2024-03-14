#include "syscalls.h"
#include "DkomProtect.h"
#include "IrpProtect.h"


VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrintEx(0, 0, "ProtectionDriver - Unload called\n");
    FreeProtectedFunctions();
    FreeProtectedDrivers();
    UnhookNtLoadDriver();
    ContextSwitchProtection::UninstallSwapContextHook();
}


extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    DriverObject->DriverUnload = (PDRIVER_UNLOAD)DriverUnload;
    DbgPrintEx(0, 0, "\n--------------------\n"
        "         _            _   _         _     _      _            _            _     _          _  \n"
        "        /\\_\\         /\\_\\/\\_\\ _    /\\ \\ /_/\\    /\\ \\         /\\ \\         /\\ \\  /\\ \\    _ / /\\ \n"
        "       / / /  _     / / / / //\\_\\ /  \\ \\\\ \\ \\   \\ \\_\\       /  \\ \\____   /  \\ \\ \\ \\ \\  /_/ / / \n"
        "      / / /  /\\_\\  /\\ \\/ \\ \\/ / // /\\ \\ \\\\ \\ \\__/ / /      / /\\ \\_____\\ / /\\ \\ \\ \\ \\ \\ \\___\\/  \n"
        "     / / /__/ / / /  \\____\\__/ // / /\\ \\_\\\\ \\__ \\/_/      / / /\\/___  // / /\\ \\_\\/ / /  \\ \\ \\  \n"
        "    / /\\_____/ / / /\\/________// /_/_ \\/_/ \\/_/\\__/\\     / / /   / / // / /_/ / /\\ \\ \\   \\_\\ \\ \n"
        "   / /\\_______/ / / /\\/_// / // /____/\\     _/\\/__\\ \\   / / /   / / // / /__\\/ /  \\ \\ \\  / / / \n"
        "  / / /\\ \\ \\   / / /    / / // /\\____\\/    / _/_/\\ \\ \\ / / /   / / // / /_____/    \\ \\ \\/ / /  \n"
        " / / /  \\ \\ \\ / / /    / / // / /______   / / /   \\ \\ \\\\ \\ \\__/ / // / /\\ \\ \\       \\ \\ \\/ /   \n"
        "/ / /    \\ \\ \\\\/_/    / / // / /_______\\ / / /    /_/ / \\ \\___\\/ // / /  \\ \\ \\       \\ \\  /    \n"
        "\\/_/      \\_\\_\\       \\/_/ \\/__________/ \\/_/     \\_\\/   \\/_____/ \\/_/    \\_\\/        \\_\\/     \n"
        "Discord: bldysis#0868  GitHub: shaygitub\n"
        "--------------------\n");


    // SSDT safe-hook NtLoadDriver() to monitor loading drivers:
    Status = SSDT::SystemServiceDTHook(&NtLoadDriverProtection, NTLOADDRIVER_TAG);
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(0, 0, "ProtectionDriver - Failed to safe-hook NtLoadDriver() for monitoring vulnurable drivers, status code: 0x%x\n", Status);
        DriverUnload(DriverObject);  // Clean all existing hooks
        return STATUS_UNSUCCESSFUL;
    }
    

    // Install HalClearLastBranchRecordStack() hook to monitor running threads:
    Status = ContextSwitchProtection::InstallSwapContextHook();
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(0, 0, "ProtectionDriver - Failed to install HalClearLastBranchRecordStack() hook to monitor running threads, status code: 0x%x\n", Status);
        DriverUnload(DriverObject);  // Clean all existing hooks
        return STATUS_UNSUCCESSFUL;
    }


    // Execute system calls protection thread:
    HANDLE SyscallProtThread = NULL;
    Status = PsCreateSystemThread(
        &SyscallProtThread,
        GENERIC_ALL,
        NULL,
        NULL,
        NULL,
        (PKSTART_ROUTINE)SystemCallsProtection,
        NULL);
    
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(0, 0, "ProtectionDriver - Failed to create system calls protection thread, status code: 0x%x\n", Status);
        DriverUnload(DriverObject);  // Clean all existing hooks
        return STATUS_UNSUCCESSFUL;
    }
    ZwClose(SyscallProtThread);


    // Execute IRP protection thread:
    HANDLE IrpProtThread = NULL;
    Status = PsCreateSystemThread(
        &IrpProtThread,
        GENERIC_ALL,
        NULL,
        NULL,
        NULL,
        (PKSTART_ROUTINE)IrpPatchProtection,
        NULL);

    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(0, 0, "ProtectionDriver - Failed to create IRP protection thread, status code: 0x%x\n", Status);
        DriverUnload(DriverObject);  // Clean all existing hooks
        return STATUS_UNSUCCESSFUL;
    }
    ZwClose(IrpProtThread);
    return Status;
}