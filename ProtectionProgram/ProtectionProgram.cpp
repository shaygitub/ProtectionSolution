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
    HRESULT Res = S_OK;


    // HARDCODED VALUES, CHANGE THIS BY ListAttacker IF NEEDED
    const char* FileHostAddresses = "192.168.1.21~192.168.1.10~192.168.40.1";
    printf("[+] Welcome to the setup of the KMEX protection solution!\n");


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
    system("sc stop ProtectionService");
    system("sc delete ProtectionService");
    wcscat_s(ServiceCreateCommand, L"sc create ProtectionService type=own start=auto binPath=\"");
    wcscat_s(ServiceCreateCommand, AppDataPath);
    wcscat_s(ServiceCreateCommand, L"\\ProtectionSolution\\Service\\ProtectionService.exe\"");
    if (_wsystem(ServiceCreateCommand) == -1) {
        printf("[-] Failed to create protection service: %d\n", GetLastError());
        return FALSE;
    }
    printf("[+] Created protection service\n");


    // Create the service for the driver:
    system("sc stop ProtectionDriver");
    system("sc delete ProtectionDriver");
    wcscat_s(DriverServiceCreateCommand, L"sc create ProtectionDriver type=kernel start=auto binPath=\"");
    wcscat_s(DriverServiceCreateCommand, AppDataPath);
    wcscat_s(DriverServiceCreateCommand, L"\\ProtectionSolution\\KernelDriver\\ProtectionDriver.sys\"");
    if (_wsystem(DriverServiceCreateCommand) == -1) {
        printf("[-] Failed to create protection driver service: %d\n", GetLastError());
        return FALSE;
    }
    printf("[+] Created protection driver service\n");


    // Turn off KPP:
    if (system("bcdedit /debug ON") == -1) {
        printf("[-] Failed to turn off KPP: %d\n", GetLastError());
        return FALSE;
    }
    printf("[+] Turned off KPP\n");


    // Forcefully restart machine:
    if (system("shutdown -r -f > nul") == -1) {
        printf("[-] Failed to force reset the protected machine: %d\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}