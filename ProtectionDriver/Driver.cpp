
#include "syscalls.h"


VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrintEx(0, 0, "ProtectionDriver - Unload called\n");
    FreeProtectedFunctions();
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


    // SSDT safe-hook NtLoadDriver to monitor loading drivers:
    Status = SSDT::SystemServiceDTHook(&NtLoadDriverProtection, NTLOADDRIVER_TAG);
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(0, 0, "ProtectionDriver - Failed to safe-hook NtLoadDriver() for monitoring vulnurable drivers, status code: 0x%x\n", Status);
        return STATUS_UNSUCCESSFUL;
    }


    // Execute system calls protection thread:
    HANDLE PipeThread = NULL;
    Status = PsCreateSystemThread(
        &PipeThread,
        GENERIC_ALL,
        NULL,
        NULL,
        NULL,
        (PKSTART_ROUTINE)SystemCallsProtection,
        NULL);
    
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(0, 0, "ProtectionDriver - Failed to create system calls protection thread, status code: 0x%x\n", Status);
        if (PipeThread != NULL) {
            ZwClose(PipeThread);
        }
        return STATUS_UNSUCCESSFUL;
    }
    ZwClose(PipeThread);
    return Status;
}