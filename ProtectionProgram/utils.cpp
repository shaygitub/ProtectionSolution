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
    if (_wsystem(ServiceCommandPath) == -1 || _wsystem(DriverCheckerCommandPath) == -1 ||
        _wsystem(KernelDriverCommandPath) == -1 || _wsystem(ExtraFilesCommandPath) == -1) {
        return GetLastError();
    }
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
        "if not exist ProtectionService.exe curl http://~:45454/ProtectionService/x64/Release/ProtectionService.exe --output ProtectionService.exe && ",
         "cd `\\ProtectionSolution\\KernelDriver\\ && ",
        "if not exist ProtectionDriver.sys curl http://~:45454/ProtectionDriver/x64/Release/ProtectionDriver.sys --output ProtectionDriver.sys && ",
         "cd `\\ProtectionSolution\\DriverChecker\\ && ",
        "if not exist ScWrapper.exe curl http://~:45454/ProtectionDriverChecker/ScWrapper/ProtectionDriverChecker.exe --output ScWrapper.exe" };
    const char* ReplaceArr[2] = { AppDataPathReg, FileHostIp };
    const char* SymbolsArr = "`~";
    const int TotalCommands = 6;
    if (!PerformCommand(FileCommands, ReplaceArr, SymbolsArr, TotalCommands, 2)) {
        return (int)GetLastError();
    }
    return 0;
}