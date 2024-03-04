#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WS2tcpip.h>
#include <winsock2.h>
#include <Windows.h>
#include <random>
#include <Psapi.h>
#include <TlHelp32.h>
#include <winnt.h>
#include <iostream>
#include <stdint.h>
#define MAXIPV4_ADDRESS_SIZE 16  // 3 * 4 triple digit numbers + 3 dots + null terminator


typedef struct _REPLACEMENT {
    char* Replace;
    char WhereTo;
    int RepCount;
} REPLACEMENT, * PREPLACEMENT;

int CharpToWcharp(const char* ConvertString, WCHAR* ConvertedString);
int WcharpToCharp(char* ConvertedString, const WCHAR* ConvertString);
DWORD CompareIpAddresses(char* LocalHost, const char* RemoteAddr);
BOOL MatchIpAddresses(char GetMatchedIp[], char MatchFromIp[], const char* MatchingAddresses);
int CountOccurrences(const char* SearchStr, char SearchLetter);
void ReplaceValues(const char* BaseString, REPLACEMENT RepArr[], char* Output, int Size);
DWORD ExecuteSystem(const char* BaseCommand, REPLACEMENT RepArr[], int Size);
void GetRandomName(char* NameBuf, DWORD RandSize, const char* Extension);
int GetPidByName(const char* Name);
int CheckLetterInArr(char Chr, const char* Arr);
BOOL PerformCommand(const char* CommandArr[], const char* Replacements[], const char* Symbols, int CommandCount, int SymbolCount);
int VerfifyDepDirs(WCHAR* AppDataPath);
int VerfifyDepFiles(const char* FileHostIp, WCHAR* AppDataPath);