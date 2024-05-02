#include "utils.h"
#include <Windows.h>
#include <stdio.h>
#include <shlobj_core.h>


int main() {
    int LastError = -1;
    char CurrentMachineIp[MAXIPV4_ADDRESS_SIZE] = { 0 };
    char FileHostIp[MAXIPV4_ADDRESS_SIZE] = { 0 };
    WCHAR* AppDataPath = NULL;
    WCHAR* ProtectionDriverPath = NULL;
    WCHAR* ProtectionServicePath = NULL;
    WCHAR ServiceCreateCommand[MAX_PATH] = { 0 };
    WCHAR DriverServiceCreateCommand[MAX_PATH] = { 0 };
    WCHAR EnvironmentVariablePath[MAX_PATH] = { 0 };
    HRESULT Res = S_OK;


    // HARDCODED VALUES, CHANGE THIS BY ListAttacker IF NEEDED
    //const char* FileHostAddresses = "192.168.1.21~192.168.1.10~192.168.40.1";
    char* FileHostAddresses = NULL;
    printf("[+] Welcome to the setup of the KMEX protection solution!\n");


    // Get the possible IP addresses for the attacker (in this case - all default gateways):
    FileHostAddresses = GetGatewayList();
    if (FileHostAddresses == NULL) {
        printf("[-] Cannot get the list of file host IP addresses!\n");
        return 0;
    }


    // Get IP addresses of protected machine and file host:
    if (!MatchIpAddresses(CurrentMachineIp, FileHostIp, FileHostAddresses)) {
        printf("[-] Cannot find the current machine address and the matching file host address!\n");
        return 0;
    }
    printf("[+] Current machine: %s, File host: %s\n", CurrentMachineIp, FileHostIp);


    // Get current user's AppData path (C:\Users\username\AppData\Roaming):
    Res = SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &AppDataPath);
    if (AppDataPath == NULL || Res != S_OK) {
        printf("[-] Cannot resolve AppData\\Roaming local path to download files, Result = %d\n", Res);
        return 0;
    }
    wprintf(L"[+] Resolved AppData\\Roaming local path: %s\n", AppDataPath);


    // Stop all processes from root directory and delete it:
    system("sc stop ProtectionService");
    system("sc delete ProtectionService");
    system("sc stop ProtectionDriver");
    system("sc delete ProtectionDriver");


    // Set up all of the needed paths and files from the file host:
    LastError = VerfifyDepDirs(AppDataPath);
    if (LastError != 0) {
        printf("[-] Cannot create dependent-on protection solution directorie/s, Result = %d\n", LastError);
        return LastError;
    }
    LastError = VerfifyDepFiles(FileHostIp, AppDataPath);
    if (LastError != 0) {
        printf("[-] Cannot download dependent-on protection solution file/s, Result = %d\n", LastError);
        return LastError;
    }


    // Create the service for the service:
    wcscat_s(ServiceCreateCommand, L"C:\\Windows\\System32\\sc.exe create ProtectionService type=own start=auto binPath=\"");
    wcscat_s(ServiceCreateCommand, AppDataPath);
    wcscat_s(ServiceCreateCommand, L"\\ProtectionSolution\\Service\\ProtectionService.exe\"");
    if (_wsystem(ServiceCreateCommand) == -1) {
        printf("[-] Failed to create protection service: %d\n", GetLastError());
        return FALSE;
    }
    printf("[+] Created protection service\n");

    
    // Create the service for the driver (start=system to load before other auto/demand services):
    wcscat_s(DriverServiceCreateCommand, L"C:\\Windows\\System32\\sc.exe create ProtectionDriver type=kernel start=system binPath=\"");
    wcscat_s(DriverServiceCreateCommand, AppDataPath);
    wcscat_s(DriverServiceCreateCommand, L"\\ProtectionSolution\\KernelDriver\\ProtectionDriver.sys\"");
    if (_wsystem(DriverServiceCreateCommand) == -1) {
        printf("[-] Failed to create protection driver service: %d\n", GetLastError());
        return FALSE;
    }
    printf("[+] Created protection driver service\n");


    // Verify if shortcut to wrappers dont point to wrappers, if so - link again:
    wcscat_s(EnvironmentVariablePath, AppDataPath);
    wcscat_s(EnvironmentVariablePath, L"\\ProtectionSolution\\DriverChecker");
    LastError = AddPathToEnvVariable(EnvironmentVariablePath);
    if (LastError != 0) {
        printf("[-] Failed to add new sc.exe path: %d\n", LastError);
        return FALSE;
    }
    printf("[+] Added new sc.exe path\n");


    // Turn on all of the important security features ():
    // TODO
    

    // Turn off KPP:
    if (system("bcdedit /debug ON") == -1) {
        printf("[-] Failed to turn off KPP: %d\n", GetLastError());
        return FALSE;
    }
    printf("[+] Turned off KPP\n");


    // Forcefully restart machine:
    if (system("shutdown -r -f -t 1 > nul") == -1) {
        printf("[-] Failed to force reset the protected machine: %d\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}