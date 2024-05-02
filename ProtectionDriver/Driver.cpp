#include "syscalls.h"
#include "DkomProtect.h"
#include "IrpProtect.h"


// Global variables:
THREAD_STATUS IrpThreadStop = StartStatus;
THREAD_STATUS SyscallThreadStop = StartStatus;
THREAD_STATUS HiddenProcsThreadStop = StartStatus;


VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrintEx(0, 0, "ProtectionDriver - Unload called\n");
    if (IrpThreadStop != FinishedStatus) {
        IrpThreadStop = TerminateStatus;
    }
    if (SyscallThreadStop != FinishedStatus) {
        SyscallThreadStop = TerminateStatus;
    }
    if (HiddenProcsThreadStop != FinishedStatus) {
        HiddenProcsThreadStop = TerminateStatus;
    }
    while (IrpThreadStop != FinishedStatus || SyscallThreadStop != FinishedStatus ||
        HiddenProcsThreadStop != FinishedStatus) {
    }  // Each protection thread will change these to FinishedStatus when terminated
    HiddenProcessesProtection::ProcessList::FreeList();
    // FreeProtectedFunctions();
    // FreeProtectedDrivers();
    // ContextSwitchProtection::UninstallSwapContextHook();
}


extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    const char* HelloMessage1 = "\n--------------------\n"
        " _   _____  ___ _______   __  ____________ _____ _   _ ___________ \n"
        "| | / /|  \\/  ||  ___\\ \\ / /  |  _  \\ ___ \\_   _| | | |  ___| ___ \\\n"
        "| |/ / | .  . || |__  \\ V /   | | | | |_/ / | | | | | | |__ | |_/ /\n"
        "|    \\ | |\\/| ||  __| /   \\   | | | |    /  | | | | | |  __||    / \n";
        
    const char* HelloMessage2 = 
        "| |\\  \\| |  | || |___/ /^\\ \\  | |/ /| |\\ \\ _| |_\\ \\_/ / |___| |\\ \\ \n"
        "\\_| \\_/\\_|  |_/\\____/\\/   \\/  |___/ \\_| \\_|\\___/ \\___/\\____/\\_| \\_|\n\n"
        "Discord: bldysis#0868  GitHub: shaygitub\n"
        "--------------------\n";

    DriverObject->DriverUnload = (PDRIVER_UNLOAD)DriverUnload;
    DbgPrintEx(0, 0, HelloMessage1);
    DbgPrintEx(0, 0, HelloMessage2);


    // Initialize SSDT parameters:
    if (!NT_SUCCESS(SSDT::InitializeSSDTParameters())) {
        DbgPrintEx(0, 0, "ProtectionDriver - Failed to initialize SSDT parameters, status code: 0x%x\n", Status);
        DriverUnload(DriverObject);  // Clean all existing hooks
        return STATUS_UNSUCCESSFUL;
    }


    /*
    // Install HalClearLastBranchRecordStack() hook to monitor running threads:
    Status = ContextSwitchProtection::InstallSwapContextHook();
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(0, 0, "ProtectionDriver - Failed to install HalClearLastBranchRecordStack() hook to monitor running threads, status code: 0x%x\n", Status);
        DriverUnload(DriverObject);  // Clean all existing hooks
        return STATUS_UNSUCCESSFUL;
    }
    */


    // Execute system calls protection thread:
    HANDLE HiddenProcsProtThread = NULL;
    Status = PsCreateSystemThread(
        &HiddenProcsProtThread,
        GENERIC_ALL,
        NULL,
        NULL,
        NULL,
        (PKSTART_ROUTINE)HiddenProcessesProtection::HiddenProcessProtection,
        (PVOID)&HiddenProcsThreadStop);

    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(0, 0, "ProtectionDriver - Failed to create hidden processes protection thread, status code: 0x%x\n", Status);
        DriverUnload(DriverObject);  // Clean all existing hooks
        return STATUS_UNSUCCESSFUL;
    }
    ZwClose(HiddenProcsProtThread);


    // Execute system calls protection thread:
    HANDLE SyscallProtThread = NULL;
    Status = PsCreateSystemThread(
        &SyscallProtThread,
        GENERIC_ALL,
        NULL,
        NULL,
        NULL,
        (PKSTART_ROUTINE)SystemCallsProtection,
        (PVOID)&SyscallThreadStop);
    
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
        (PVOID)&IrpThreadStop);

    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(0, 0, "ProtectionDriver - Failed to create IRP protection thread, status code: 0x%x\n", Status);
        DriverUnload(DriverObject);  // Clean all existing hooks
        return STATUS_UNSUCCESSFUL;
    }
    ZwClose(IrpProtThread);
    return Status;
}