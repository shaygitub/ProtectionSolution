#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <iostream>
#include <bcrypt.h>
#include <ctime>
#include "vulnurable_list.h"
#define STATUS_SUCCESS 0
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define SHA256_HASHSIZE 33
#define VULNLIST_SIZE 407


std::wstring GetCurrentWorkingDirectory() {
	TCHAR buffer[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, buffer, MAX_PATH);
	std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
	return std::wstring(buffer).substr(0, pos);
}


void JoinCommandLineArguments(char* CommandBuffer, char* argv[], int argc) {
	ULONG CurrentOffset = 0;
	if (CommandBuffer != NULL && argv != NULL && argc != 0) {
		for (int ParamIndex = 0; ParamIndex < argc; ParamIndex++) {
			RtlCopyMemory((PVOID)((ULONG64)CommandBuffer + CurrentOffset),
				argv[ParamIndex], strlen(argv[ParamIndex]));
			CurrentOffset += strlen(argv[ParamIndex]);
			if (ParamIndex != argc - 1) {
				CommandBuffer[CurrentOffset] = ' ';
				CurrentOffset++;
			}
		}
		CommandBuffer[CurrentOffset] = '\0';
	}
}


int CallActualUtility(const char* ActualUtility, char* CommandToExecute,
	int argc, char* argv[]) {
	argv[0] = (char*)ActualUtility;
	JoinCommandLineArguments(CommandToExecute, argv, argc);
	printf("%s\n", CommandToExecute);
	return system(CommandToExecute);
}


int FileOperation(char* FilePath, HANDLE* FileHandle, PVOID* FileData,
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


NTSTATUS CreateDataHash(PVOID DataToHash, ULONG SizeOfDataToHash, LPCWSTR HashName,
	PVOID* HashedDataOutput, ULONG* HashedDataLength) {
	/*
	Note: hash name is the documented macro for the type of encryption
	documented in https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
	*/
	NTSTATUS Status = STATUS_SUCCESS;
	BCRYPT_ALG_HANDLE HashAlgorithm = { 0 };
	BCRYPT_HASH_HANDLE HashHandle = { 0 };
	ULONG HashObjectLength = 0;
	ULONG HashObjLengthWritten = 0;
	ULONG HashDataLength = 0;
	ULONG HashDataLengthWritten = 0;
	PVOID HashObject = NULL;
	PVOID HashedData = NULL;
	BOOL HashHandleCreated = FALSE;
	BOOL HashProviderCreated = FALSE;


	// Make sure no invalid parameters are provided (no need to enforce outputed hashed data length):
	if (HashName == NULL || DataToHash == NULL || HashedDataOutput == NULL) {
		return STATUS_INVALID_PARAMETER;
	}


	// Create the hashing algorithm provider handle to hash the data:
	Status = BCryptOpenAlgorithmProvider(&HashAlgorithm, HashName, NULL, 0);
	if (!NT_SUCCESS(Status)) {
		goto CleanUp;
	}
	HashProviderCreated = TRUE;


	// Get the needed length for the hashing object and allocate a non-paged pool for the object:
	Status = BCryptGetProperty(HashAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&HashObjectLength,
		sizeof(HashObjectLength), &HashObjLengthWritten, 0);
	if (!NT_SUCCESS(Status) || HashObjLengthWritten != sizeof(HashObjectLength)) {
		if (NT_SUCCESS(Status)) {
			Status = STATUS_FATAL_APP_EXIT;  // In this case not all the data size was written
		}
		goto CleanUp;
	}
	HashObject = malloc(HashObjectLength);
	if (HashObject == NULL) {
		Status = STATUS_NO_MEMORY;
		goto CleanUp;
	}


	// Create the hashing object used to hash the actual data:
	Status = BCryptCreateHash(HashAlgorithm, &HashHandle, (PUCHAR)HashObject, HashObjectLength, NULL, 0, 0);
	if (!NT_SUCCESS(Status)) {
		goto CleanUp;
	}
	HashHandleCreated = TRUE;


	// Get the hashed data size and allocate a non-paged pool for the hashed data:
	Status = BCryptGetProperty(HashAlgorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&HashDataLength,
		sizeof(HashDataLength), &HashDataLengthWritten, 0);
	if (!NT_SUCCESS(Status) || HashDataLengthWritten != sizeof(HashDataLength)) {
		if (NT_SUCCESS(Status)) {
			Status = STATUS_FATAL_APP_EXIT;  // In this case not all the data size was written
		}
		goto CleanUp;
	}
	HashedData = malloc(HashDataLength);
	if (HashedData == NULL) {
		Status = STATUS_NO_MEMORY;
		goto CleanUp;
	}


	// Hash the actual data:
	Status = BCryptHashData(HashHandle, (PUCHAR)DataToHash, SizeOfDataToHash, 0);
	if (!NT_SUCCESS(Status)) {
		goto CleanUp;
	}


	// Get the hash value (hash handle cannot be reused after this operation) and return it to caller:
	Status = BCryptFinishHash(HashHandle, (PUCHAR)HashedData, HashDataLength, 0);
	if (!NT_SUCCESS(Status)) {
		goto CleanUp;
	}


	// Clean up and return successfully:
CleanUp:
	if (HashHandleCreated) {
		BCryptDestroyHash(HashHandle);
	}
	if (HashProviderCreated) {
		BCryptCloseAlgorithmProvider(HashAlgorithm, 0);
	}
	if (HashObject != NULL) {
		free(HashObject);
	}
	if (HashedData != NULL && !NT_SUCCESS(Status)) {
		free(HashedData);  // Note: dont free HashedData if succeeded, will hold the hashed data
		HashedData = NULL;
		HashedDataLength = 0;
	}
	*HashedDataOutput = HashedData;
	if (HashedDataLength != NULL) {
		*HashedDataLength = HashDataLength;
	}
	return Status;
}


DWORD WriteToLog(LPCWSTR LogFileName, std::wstring LogDirectory, char* LogData, int VulnIndex) {
	HANDLE LogHandle = INVALID_HANDLE_VALUE;
	DWORD LogWritten = 0;
	char FixedLogData[MAX_PATH * 2] = { 0 };
	char IndexString[10] = { 0 };
	char TimeString[MAX_PATH] = { 0 };
	time_t RawTimestamp;
	struct tm* TimestampInfo;
	LogDirectory.append(L"\\");
	LogDirectory.append(LogFileName);


	// Get current timestamp for logging:
	time(&RawTimestamp);
	TimestampInfo = localtime(&RawTimestamp);
	strftime(TimeString, sizeof(TimeString), "%d-%m-%Y %H:%M:%S", TimestampInfo);
	
	
	// Create/open logging file:
	LogHandle = CreateFileW(LogDirectory.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (LogHandle == INVALID_HANDLE_VALUE) {
		return GetLastError();
	}
	SetFilePointer(LogHandle, 0, NULL, FILE_END);  // Append data


	// Resolve data to write into logging file:
	strcat_s(FixedLogData, TimeString);
	strcat_s(FixedLogData, " The file ");
	strcat_s(FixedLogData, LogData);
	if (VulnIndex >= 0) {
		strcat_s(FixedLogData, " is vulnurable, index ");
		_itoa_s(VulnIndex, IndexString, 10);
		strcat_s(FixedLogData, IndexString);
		strcat_s(FixedLogData, "\n");
	}
	else {
		strcat_s(FixedLogData, " is not vulnurable\n");
	}
	if (!WriteFile(LogHandle, FixedLogData, strlen(FixedLogData), &LogWritten, NULL) ||
		LogWritten != strlen(FixedLogData)) {
		CloseHandle(LogHandle);
		return GetLastError();
	}
	CloseHandle(LogHandle);
	return 0;
}


BOOL AnalyzeFilePath(char* FilePath, char* ServiceName) {
	HANDLE FileHandle = INVALID_HANDLE_VALUE;
	PVOID FileData = NULL;
	ULONG64 FileSize = NULL;
	PVOID HashedFileData = NULL;
	ULONG HashedFileSize = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	char DeleteCommand[MAX_PATH] = { 0 };
	char UnloadCommand[MAX_PATH] = { 0 };
	int LastError = FileOperation(FilePath, &FileHandle, &FileData, &FileSize, FALSE, FALSE);
	if (LastError != 0) {
		printf("[-] Reading image %s information failed - %d, %d\n", FilePath, LastError,
			GetLastError());
		return FALSE;
	}


	// Hash the file information;
	Status = CreateDataHash(FileData, FileSize, BCRYPT_SHA256_ALGORITHM,
		&HashedFileData, &HashedFileSize);
	if (!NT_SUCCESS(Status) || HashedFileSize == 0 || HashedFileData == NULL) {
		if (HashedFileData != NULL) {
			free(HashedFileData);
		}
		if (FileData != NULL) {
			free(FileData);
		}
		printf("[-] Failed to create SHA256 of image %s - 0x%x\n", FilePath, Status);
		return FALSE;
	}


	// Compare the driver's SHA256 hash to the vulnurable list:
	for (ULONG VulnHashIndex = 0; VulnHashIndex < VULNLIST_SIZE; VulnHashIndex++) {
		if (RtlCompareMemory(VulnurableByteList[VulnHashIndex], HashedFileData, SHA256_HASHSIZE) == SHA256_HASHSIZE) {
			printf("[!] Warning: vulnurable driver found at %s, deleting driver file ..\n", FilePath);
			strcat_s(UnloadCommand, "C:\\Windows\\System32\\sc.exe stop ");
			strcat_s(UnloadCommand, ServiceName);
			strcat_s(UnloadCommand, " && C:\\Windows\\System32\\sc.exe delete ");
			strcat_s(UnloadCommand, ServiceName);
			strcat_s(DeleteCommand, "del /s /q ");
			strcat_s(DeleteCommand, FilePath);
			system(UnloadCommand);
			system(DeleteCommand);
			WriteToLog(L"ScVulnFile.txt", GetCurrentWorkingDirectory(), FilePath, TRUE);
			return TRUE;
		}
	}
	if (HashedFileData != NULL) {
		free(HashedFileData);
	}
	if (FileData != NULL) {
		free(FileData);
	}
	WriteToLog(L"ScVulnFile.txt", GetCurrentWorkingDirectory(), FilePath, FALSE);
	printf("[+] Image %s is not vulnurable\n", FilePath);
	return FALSE;
}


int main(int argc, char* argv[]) {
	const char* ActualUtility = "C:\\Windows\\System32\\sc.exe";
	char CommandToExecute[512] = { 0 };
	char PathInSameParameter[512] = { 0 };
	char ServiceName[MAX_PATH] = { 0 };
	std::string CurrentParameter;
	SIZE_T ParamPosition = 0;
	BOOL FoundBinPath = FALSE;
	struct stat CheckExists = { 0 };

	if (argc < 3 || strcmp(argv[1], "create") != 0) {
		return CallActualUtility(ActualUtility, CommandToExecute, argc, argv);
	}
	RtlCopyMemory(ServiceName, argv[2], strlen(argv[2]) + 1);
	for (int ParamIndex = 3; ParamIndex < argc; ParamIndex++) {
		CurrentParameter.append(argv[ParamIndex]);
		if (FoundBinPath) {
			if (argv[ParamIndex] != "" && argv[ParamIndex] != " ") {
				if (stat(argv[ParamIndex], &CheckExists) == 0) {
					if (AnalyzeFilePath(argv[ParamIndex], ServiceName)) {
						return 0;
					}
					break;
				}
			}
		}
		ParamPosition = CurrentParameter.find("binPath=", 0);
		if (ParamPosition == 0) {
			if (RtlCompareMemory(argv[ParamIndex], "binPath=", strlen("binPath=") + 1)
				== strlen("binPath=") + 1) {

				// Parameter should be in next argument:
				FoundBinPath = TRUE;
			}
			else {

				// Path is in this parameter:
				RtlZeroMemory(PathInSameParameter, 512);
				RtlCopyMemory(PathInSameParameter, argv[ParamIndex] + strlen("binPath="),
					strlen(argv[ParamIndex] + strlen("binPath=")) + 1);
				if (stat(PathInSameParameter, &CheckExists) == 0) {
					if (AnalyzeFilePath(PathInSameParameter, ServiceName)) {
						return 0;
					}
					break;
				}
			}
		}
		CurrentParameter.erase(0, CurrentParameter.length());
	}
	return CallActualUtility(ActualUtility, CommandToExecute, argc, argv);
}