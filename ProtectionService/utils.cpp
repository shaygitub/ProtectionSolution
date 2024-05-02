#include "utils.h"


int CharpToWcharp(const char* ConvertString, WCHAR* ConvertedString) {
    int WideNameLen = MultiByteToWideChar(CP_UTF8, 0, ConvertString, -1, NULL, 0);
    MultiByteToWideChar(CP_UTF8, 0, ConvertString, -1, ConvertedString, WideNameLen);
    return WideNameLen;
}


int WcharpToCharp(char* ConvertedString, const WCHAR* ConvertString) {
    int MultiByteLen = WideCharToMultiByte(CP_UTF8, 0, ConvertString, -1, NULL, 0, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, ConvertString, -1, ConvertedString, MultiByteLen, NULL, NULL);
    return MultiByteLen;
}


DWORD CompareIpAddresses(char* LocalHost, const char* RemoteAddr) {
    DWORD Score = 0;
    DWORD LocalInd = 0;
    DWORD RemoteInd = 0;
    DWORD MaskValue = 0x80;
    DWORD CurrMask = 0x80;
    DWORD MatchingFields = 0;
    DWORD LocalNumeric = 0;
    DWORD RemoteNumeric = 0;

    while (MatchingFields != 4) {
        while (LocalHost[LocalInd] != '.' && LocalHost[LocalInd] != '\0') {
            LocalNumeric *= 10;
            LocalNumeric += (LocalHost[LocalInd] - 0x30);
            LocalInd++;
        }

        while (RemoteAddr[RemoteInd] != '.' && RemoteAddr[RemoteInd] != '\0') {
            RemoteNumeric *= 10;
            RemoteNumeric += (RemoteAddr[RemoteInd] - 0x30);
            RemoteInd++;
        }

        while (CurrMask != 0) {
            if ((RemoteNumeric & CurrMask) == (LocalNumeric & CurrMask)) {
                Score++;
            }
            else {
                return Score;
            }
            CurrMask /= 2;
        }
        RemoteInd++;
        LocalInd++;
        MatchingFields++;
        LocalNumeric = 0;
        RemoteNumeric = 0;
        CurrMask = MaskValue;
    }
    return Score;  // If got here - 32, probably not possible, exactly like current IP address
}


BOOL MatchIpAddresses(char GetMatchedIp[], char MatchFromIp[], const char* MatchingAddresses) {
    char LocalHostName[80];
    char* CurrIp = NULL;
    char CurrAttacker[MAXIPV4_ADDRESS_SIZE] = { 0 };

    struct hostent* LocalIpsList = NULL;
    DWORD CompareScore = 0;
    DWORD CurrentScore = 0;
    DWORD AddrIndex = 0;
    DWORD AttackIndex = 0;
    WSADATA SockData = { 0 };
    if (WSAStartup(MAKEWORD(2, 2), &SockData) != 0) {
        return FALSE;
    }


    // Get the hostname of the local machine to get ip addresses -
    if (gethostname(LocalHostName, sizeof(LocalHostName)) == SOCKET_ERROR) {
        printf("%d when getting local host name!", WSAGetLastError());
        WSACleanup();
        return FALSE;
    }
    LocalIpsList = gethostbyname(LocalHostName);
    if (LocalIpsList == 0) {
        WSACleanup();
        return FALSE;
    }


    // Find the address pair with the most similar bits in the address -
    while (AddrIndex < strlen(MatchingAddresses)) {
        while (MatchingAddresses[AddrIndex] != '~' && MatchingAddresses[AddrIndex] != '\0') {
            CurrAttacker[AttackIndex] = MatchingAddresses[AddrIndex];
            AddrIndex++;
            AttackIndex++;
        }
        CurrAttacker[AttackIndex] = '\0';
        AttackIndex = 0;
        if (MatchingAddresses[AddrIndex] == '~') {
            AddrIndex++;
        }

        for (int i = 0; LocalIpsList->h_addr_list[i] != 0; ++i) {
            struct in_addr addr;
            memcpy(&addr, LocalIpsList->h_addr_list[i], sizeof(struct in_addr));
            CurrIp = inet_ntoa(addr);
            CurrentScore = CompareIpAddresses(CurrIp, CurrAttacker);
            if (CurrentScore > CompareScore) {
                CompareScore = CurrentScore;
                RtlZeroMemory(GetMatchedIp, MAXIPV4_ADDRESS_SIZE);
                RtlZeroMemory(MatchFromIp, MAXIPV4_ADDRESS_SIZE);
                memcpy(GetMatchedIp, CurrIp, strlen(CurrIp) + 1);
                memcpy(MatchFromIp, CurrAttacker, strlen(CurrAttacker) + 1);
            }
        }
    }

    WSACleanup();
    return TRUE;
}


int CountOccurrences(const char* SearchStr, char SearchLetter) {
    DWORD Count = 0;
    for (int i = 0; i < strlen(SearchStr); i++) {
        if (SearchStr[i] == SearchLetter) {
            Count++;
        }
    }
    return Count;
}


void ReplaceValues(const char* BaseString, REPLACEMENT RepArr[], char* Output, int Size) {
    int ii = 0;
    int repi = 0;
    int comi = 0;

    for (int i = 0; i <= strlen(BaseString); i++) {
        if (repi < Size && BaseString[i] == RepArr[repi].WhereTo) {
            memcpy((PVOID)((ULONG64)Output + comi), RepArr[repi].Replace, strlen(RepArr[repi].Replace));
            comi += strlen(RepArr[repi].Replace);

            RepArr[repi].RepCount -= 1;
            if (RepArr[repi].RepCount == 0) {
                repi++;
            }
        }
        else {
            Output[comi] = BaseString[i];
            comi++;
        }
    }
}


DWORD ExecuteSystem(const char* BaseCommand, REPLACEMENT RepArr[], int Size) {
    char Command[500] = { 0 };
    ReplaceValues(BaseCommand, RepArr, Command, Size);
    if (system(Command) == -1) {
        return GetLastError();
    }
    return 0;
}


void GetRandomName(char* NameBuf, DWORD RandSize, const char* Extension) {
    const char* Alp = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,;[]{}-_=+)(&^%$#@!~`";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distr(0, strlen(Alp) - 1);
    int i = 0;
    for (; i < (int)RandSize; i++) {
        NameBuf[i] = Alp[distr(gen)];
    }
    for (int exti = 0; exti <= strlen(Extension); exti++, i++) {
        NameBuf[i] = Extension[exti];
    }
}


int GetPidByName(const char* Name) {
    int ProcessId = 0;
    DWORD Procs[1024] = { 0 }, BytesReturned = 0, ProcessesNum = 0;
    char CurrentName[MAX_PATH] = { 0 };
    HANDLE CurrentProc = INVALID_HANDLE_VALUE;
    HMODULE CurrentProcMod = NULL;

    // Get the list of PIDs of all running processes -   
    if (!EnumProcesses(Procs, sizeof(Procs), &BytesReturned))
        return 0;
    ProcessesNum = BytesReturned / sizeof(DWORD);

    for (int i = 0; i < ProcessesNum; i++) {
        if (Procs[i] != 0) {
            CurrentProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Procs[i]);
            if (CurrentProc != NULL) {
                if (EnumProcessModules(CurrentProc, &CurrentProcMod, sizeof(CurrentProcMod), &BytesReturned)) {
                    GetModuleBaseNameA(CurrentProc, CurrentProcMod, CurrentName, sizeof(CurrentName) / sizeof(TCHAR));
                    if (lstrcmpiA(Name, CurrentName) == 0) {
                        ProcessId = Procs[i];
                        break;
                    }
                }
                CloseHandle(CurrentProc);
            }
        }
    }
    return ProcessId;
}


int CheckLetterInArr(char Chr, const char* Arr) {
    for (int i = 0; i < strlen(Arr); i++) {
        if (Arr[i] == Chr) {
            return i;
        }
    }
    return -1;
}


BOOL PerformCommand(const char* CommandArr[], const char* Replacements[], const char* Symbols, int CommandCount, int SymbolCount) {
    int ActualSize = 1;
    int CurrRepIndex = 0;
    int ActualCommandIndex = 0;
    int SystemReturn = -1;

    for (int ci = 0; ci < CommandCount; ci++) {
        ActualSize += strlen(CommandArr[ci]);
        for (int si = 0; si < SymbolCount; si++) {
            ActualSize -= CountOccurrences(CommandArr[ci], Symbols[si]);
            for (int r = 0; r < CountOccurrences(CommandArr[ci], Symbols[si]); r++) {
                ActualSize += strlen(Replacements[si]);
            }
        }
    }

    char* ActualCommand = (char*)malloc(ActualSize);
    if (ActualCommand == NULL) {
        return FALSE;
    }

    for (int ci = 0; ci < CommandCount; ci++) {
        for (int cii = 0; cii < strlen(CommandArr[ci]); cii++) {
            CurrRepIndex = CheckLetterInArr(CommandArr[ci][cii], Symbols);
            if (CurrRepIndex == -1) {
                ActualCommand[ActualCommandIndex] = CommandArr[ci][cii];
                ActualCommandIndex++;
            }
            else {
                for (int ri = 0; ri < strlen(Replacements[CurrRepIndex]); ri++) {
                    ActualCommand[ActualCommandIndex] = Replacements[CurrRepIndex][ri];
                    ActualCommandIndex++;
                }
            }
        }
    }
    ActualCommand[ActualCommandIndex] = '\0';
    SystemReturn = system(ActualCommand);
    if (SystemReturn == -1) {
        free(ActualCommand);
        return FALSE;
    }
    free(ActualCommand);
    return TRUE;
}


DWORD AddPathToEnvVariable(const WCHAR* NewPathToAdd) {
    WCHAR NewEnvironmentVariable[1000] = { 0 };
    WCHAR CurrentEnvironmentVariable[1000] = { 0 };
    HKEY RegistryKeyHandle = { 0 };
    DWORD ExistingPathSize = 0;
    SIZE_T CurrentNewPathOffset = 0;
    SIZE_T LastNewPathOffset = 0;

    std::wstring NewVariableValue;
    std::wstring ExistingVariableValue;
    std::wstring PathToRemove(NewPathToAdd + L';');
    std::wstring PathToRemoveFinal(NewPathToAdd);


    // Open registry key of environment variables configurations:
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", 0,
        KEY_ALL_ACCESS, &RegistryKeyHandle) != ERROR_SUCCESS) {
        return GetLastError();
    }


    // Query the current PATH size and value in the registry key:
    if (RegQueryValueEx(RegistryKeyHandle, L"Path", NULL, NULL, NULL,
        &ExistingPathSize) != ERROR_SUCCESS) {
        RegCloseKey(RegistryKeyHandle);
        return GetLastError();
    }
    if (RegQueryValueExW(RegistryKeyHandle, L"Path", NULL, NULL,
        (LPBYTE)CurrentEnvironmentVariable, &ExistingPathSize) != ERROR_SUCCESS) {
        RegCloseKey(RegistryKeyHandle);
        return GetLastError();
    }


    // Check if path is not already at the top of the PATH variable, if so - nothing to add:
    ExistingVariableValue = CurrentEnvironmentVariable;
    if (ExistingVariableValue.find(NewPathToAdd, 0) == 0) {

        // Environment variable starts with my path already:
        NewVariableValue.append(ExistingVariableValue.c_str());
    }
    else {

        // Environment variable does not start with my path / it does not exist here:
        CurrentNewPathOffset = ExistingVariableValue.find(PathToRemoveFinal, 0);
        while (CurrentNewPathOffset != std::wstring::npos) {
            ExistingVariableValue.erase(CurrentNewPathOffset, PathToRemoveFinal.length());
            CurrentNewPathOffset = ExistingVariableValue.find(PathToRemoveFinal, 0);
        }
        NewVariableValue.append(NewPathToAdd);
        NewVariableValue.append(L";");
        NewVariableValue.append(ExistingVariableValue);
    }


    // Set the value of the PATH value to the new batch of paths:
    if (RegSetValueExW(RegistryKeyHandle, L"Path", 0, REG_EXPAND_SZ,
        (BYTE*)NewVariableValue.c_str(), (wcslen(NewVariableValue.c_str()) + 1) *
        sizeof(WCHAR)) != ERROR_SUCCESS) {
        RegCloseKey(RegistryKeyHandle);
        return GetLastError();
    }
    RegCloseKey(RegistryKeyHandle);


    // Send a global signal that the environment variables were changed (to updating them):
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment",
        SMTO_ABORTIFHUNG, 5000, NULL);
    return 0;
}


int VerfifyDepDirs(WCHAR* AppDataPath) {
    WCHAR ServicePath[MAX_PATH] = { 0 };
    WCHAR DriverCheckerPath[MAX_PATH] = { 0 };
    WCHAR KernelDriverPath[MAX_PATH] = { 0 };
    WCHAR ExtraFilesPath[MAX_PATH] = { 0 };
    WCHAR ServiceCommandPath[MAX_PATH * 2] = { 0 };
    WCHAR DriverCheckerCommandPath[MAX_PATH * 2] = { 0 };
    WCHAR KernelDriverCommandPath[MAX_PATH * 2] = { 0 };
    WCHAR ExtraFilesCommandPath[MAX_PATH * 2] = { 0 };
    if (AppDataPath == NULL) {
        return (int)ERROR_PATH_NOT_FOUND;
    }


    // Copy the initial AppData path to the start of each specific path:
    RtlCopyMemory(ServicePath, AppDataPath, (wcslen(AppDataPath) + 1) * sizeof(WCHAR));
    RtlCopyMemory(DriverCheckerPath, AppDataPath, (wcslen(AppDataPath) + 1) * sizeof(WCHAR));
    RtlCopyMemory(KernelDriverPath, AppDataPath, (wcslen(AppDataPath) + 1) * sizeof(WCHAR));
    RtlCopyMemory(ExtraFilesPath, AppDataPath, (wcslen(AppDataPath) + 1) * sizeof(WCHAR));


    // Concat the subfolder into the specific path:
    wcscat_s(ServicePath, L"\\ProtectionSolution\\Service");
    wcscat_s(DriverCheckerPath, L"\\ProtectionSolution\\DriverChecker");
    wcscat_s(KernelDriverPath, L"\\ProtectionSolution\\KernelDriver");
    wcscat_s(ExtraFilesPath, L"\\ProtectionSolution\\ExtraFiles");


    // Create the creation commands with each path string:
    wcscat_s(ServiceCommandPath, L"if not exist ");
    wcscat_s(DriverCheckerCommandPath, L"if not exist ");
    wcscat_s(KernelDriverCommandPath, L"if not exist ");
    wcscat_s(ExtraFilesCommandPath, L"if not exist ");

    wcscat_s(ServiceCommandPath, ServicePath);
    wcscat_s(DriverCheckerCommandPath, DriverCheckerPath);
    wcscat_s(KernelDriverCommandPath, KernelDriverPath);
    wcscat_s(ExtraFilesCommandPath, ExtraFilesPath);

    wcscat_s(ServiceCommandPath, L" mkdir ");
    wcscat_s(DriverCheckerCommandPath, L" mkdir ");
    wcscat_s(KernelDriverCommandPath, L" mkdir ");
    wcscat_s(ExtraFilesCommandPath, L" mkdir ");

    wcscat_s(ServiceCommandPath, ServicePath);
    wcscat_s(DriverCheckerCommandPath, DriverCheckerPath);
    wcscat_s(KernelDriverCommandPath, KernelDriverPath);
    wcscat_s(ExtraFilesCommandPath, ExtraFilesPath);


    // Create directories (if dont exist):
    _wsystem(ServiceCommandPath);
    _wsystem(DriverCheckerCommandPath);
    _wsystem(KernelDriverCommandPath);
    _wsystem(ExtraFilesCommandPath);
    return 0;
}


int VerfifyDepFiles(const char* FileHostIp, WCHAR* AppDataPath) {
    char AppDataPathReg[MAX_PATH] = { 0 };
    if (AppDataPath == NULL || FileHostIp == NULL) {
        return (int)ERROR_NOT_FOUND;
    }
    WcharpToCharp(AppDataPathReg, AppDataPath);


    // Execute commands with regular characters AppData local path and file host IP address:
    const char* FileCommands[] = { "cd `\\ProtectionSolution\\Service\\ && ",
        "if not exist ProtectionService.exe curl http://~:8080/ProtectionService/x64/Release/ProtectionService.exe --output ProtectionService.exe && ",
         "cd `\\ProtectionSolution\\KernelDriver\\ && ",
        "if not exist ProtectionDriver.sys curl http://~:8080/ProtectionDriver/x64/Release/ProtectionDriver.sys --output ProtectionDriver.sys && ",
         "cd `\\ProtectionSolution\\DriverChecker\\ && ",
        "if not exist sc.exe curl http://~:8080/ProtectionDriverChecker/x64/Release/ProtectionDriverChecker.exe --output sc.exe" };
    const char* ReplaceArr[2] = { AppDataPathReg, FileHostIp };
    const char* SymbolsArr = "`~";
    const int TotalCommands = 6;
    if (!PerformCommand(FileCommands, ReplaceArr, SymbolsArr, TotalCommands, 2)) {
        return (int)GetLastError();
    }
    return 0;
}


int OperateOnFile(char* FilePath, HANDLE* FileHandle, PVOID* FileData,
    ULONG64* FileDataSize, BOOL IsWrite, BOOL ShouldNullTerm) {
    DWORD OperationOutput = 0;
    if (FileHandle == NULL || FilePath == NULL || FileData == NULL || FileDataSize == NULL) {
        return -1;
    }
    if (IsWrite) {
        *FileHandle = CreateFileA(FilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    else {
        *FileHandle = CreateFileA(FilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    if (*FileHandle == INVALID_HANDLE_VALUE) {
        return 1;  // Invalid handle
    }
    *FileDataSize = GetFileSize(*FileHandle, 0);
    if (*FileDataSize == 0) {
        CloseHandle(*FileHandle);
        return 2;  // File size = 0
    }
    *FileData = malloc(*FileDataSize + ShouldNullTerm);  // If null terminated: needs +1 character (TRUE = 1)
    if (*FileData == NULL) {
        CloseHandle(*FileHandle);
        return 3;  // Malloc failed
    }
    if ((!IsWrite && (!ReadFile(*FileHandle, *FileData, *FileDataSize, &OperationOutput, NULL) ||
        OperationOutput != *FileDataSize)) ||
        (IsWrite && (!WriteFile(*FileHandle, *FileData, *FileDataSize, &OperationOutput, NULL) ||
            OperationOutput != *FileDataSize))) {
        CloseHandle(*FileHandle);
        free(*FileData);
        return 4;  // Actual operation failed
    }
    if (ShouldNullTerm) {
        ((char*)(*FileData))[*FileDataSize] = '\0';
    }
    CloseHandle(*FileHandle);
    return 0;
}


BOOL IsValidIp(char* Address) {
    DWORD CurrChunkValue = 0;
    if (Address == NULL || CountOccurrences(Address, '.') != 3) {
        return FALSE;
    }

    for (int i = 0; i < strlen(Address); i++) {
        if (Address[i] != '.') {
            if (isdigit(Address[i]) == 0 && Address[i]) {
                return FALSE;
            }
            CurrChunkValue *= 10;
            CurrChunkValue += (Address[i] - 0x30);
        }
        else {
            if (!(CurrChunkValue >= 0 && CurrChunkValue <= 255)) {
                return FALSE;
            }
            CurrChunkValue = 0;
        }
    }
    return TRUE;
}


char* ExtractGateways(char* IpConfigOutput) {
    SIZE_T NextGatewayOffset = 0;
    ULONG64 CurrentAddressSize = 0;
    ULONG64 OccurenceOffset = 0;
    ULONG64 GatewayBufferSize = 0;
    char CurrentAddress[MAX_PATH] = { 0 };
    char* GatewayBuffer = NULL;
    char* TemporaryBuffer = NULL;
    const char* GatewayIdentifier = "Default Gateway . . . . . . . . . : ";
    std::string StringOutput(IpConfigOutput);
    if (IpConfigOutput == NULL) {
        return NULL;
    }

    NextGatewayOffset = StringOutput.find(GatewayIdentifier, 0);
    while (NextGatewayOffset != std::string::npos) {
        OccurenceOffset = NextGatewayOffset + strlen(GatewayIdentifier);
        if (StringOutput.c_str()[OccurenceOffset] == '\r' &&
            StringOutput.c_str()[OccurenceOffset + 1] == '\n') {
            goto NextGateway;  // No gateway address specified
        }

        // Copy current address:
        for (CurrentAddressSize = 0; !(StringOutput.c_str()[OccurenceOffset + CurrentAddressSize] == '\r' &&
            StringOutput.c_str()[OccurenceOffset + CurrentAddressSize + 1] == '\n'); CurrentAddressSize++) {
            CurrentAddress[CurrentAddressSize] = StringOutput.c_str()[OccurenceOffset + CurrentAddressSize];
        }
        CurrentAddress[CurrentAddressSize] = '\0';


        // Only handle valid IPv4 addresses:
        if (IsValidIp(CurrentAddress)) {
            if (GatewayBuffer == NULL) {
                GatewayBuffer = (char*)malloc(CurrentAddressSize + 1);  // Always null terminate
                if (GatewayBuffer == NULL) {
                    return NULL;
                }
                RtlCopyMemory(GatewayBuffer, CurrentAddress, CurrentAddressSize + 1);
            }
            else {
                TemporaryBuffer = (char*)malloc(strlen(GatewayBuffer) + CurrentAddressSize + 2);  // +2 for null terminator and '~'
                if (TemporaryBuffer == NULL) {
                    free(GatewayBuffer);
                    return NULL;
                }
                RtlCopyMemory(TemporaryBuffer, GatewayBuffer, strlen(GatewayBuffer));
                TemporaryBuffer[strlen(GatewayBuffer)] = '~';
                RtlCopyMemory(TemporaryBuffer + strlen(GatewayBuffer) + 1, CurrentAddress,
                    CurrentAddressSize);
                TemporaryBuffer[strlen(GatewayBuffer) + CurrentAddressSize + 1] = '\0';
                free(GatewayBuffer);
                GatewayBuffer = TemporaryBuffer;
            }

        }
    NextGateway:
        NextGatewayOffset = StringOutput.find(GatewayIdentifier, NextGatewayOffset + strlen(GatewayIdentifier));
    }
    return GatewayBuffer;
}


char* GetGatewayList() {
    HANDLE FileHandle = INVALID_HANDLE_VALUE;
    ULONG64 FileDataSize = 0;
    char* FileData = NULL;
    char* FilteredData = NULL;
    system("ipconfig /all > IpConfigOutput");
    if (OperateOnFile((char*)"IpConfigOutput", &FileHandle, (PVOID*)&FileData, &FileDataSize, FALSE, TRUE) != 0 ||
        FileHandle == NULL) {
        return NULL;
    }
    FilteredData = ExtractGateways(FileData);
    free(FileData);
    system("del /s /q IpConfigOutput");
    return FilteredData;
}