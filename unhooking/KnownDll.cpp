#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <algorithm>
#include <string>
#define NTDLL	L"\\KnownDlls\\ntdll.dll"

typedef NTSTATUS(NTAPI* fnNtOpenSection)(
	PHANDLE               SectionHandle,
	ACCESS_MASK           DesiredAccess,
	POBJECT_ATTRIBUTES    ObjectAttributes
	);

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

		// if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
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

BOOL MapNtdllFromKnownDlls(OUT PVOID* ppNtdllBuf) {

	HANDLE    		    hSection = NULL;
	PBYTE     		    pNtdllBuffer = NULL;
	NTSTATUS            	STATUS = NULL;
	UNICODE_STRING      	UniStr = { 0 };
	OBJECT_ATTRIBUTES  	ObjAtr = { 0 };

	UniStr.Buffer = (PWSTR)NTDLL;
	UniStr.Length = wcslen(NTDLL) * sizeof(WCHAR);
	UniStr.MaximumLength = UniStr.Length + sizeof(WCHAR);

	InitializeObjectAttributes(&ObjAtr, &UniStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

	fnNtOpenSection pNtOpenSection = (fnNtOpenSection)GetProcAddress(GetModuleHandle(L"NTDLL"), "NtOpenSection");

	STATUS = pNtOpenSection(&hSection, SECTION_MAP_READ, &ObjAtr);
	if (STATUS != 0x00) {
		printf("[!] NtOpenSection Failed With Error : 0x%0.8X \n", STATUS);
		goto _EndOfFunc;
	}

	pNtdllBuffer = (PBYTE)MapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
	if (pNtdllBuffer == NULL) {
		printf("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	*ppNtdllBuf = pNtdllBuffer;

_EndOfFunc:
	if (hSection)
		CloseHandle(hSection);
	if (*ppNtdllBuf == NULL)
		return FALSE;
	else
		return TRUE;
}
int main() {
	PVOID ppNtdllBuf = NULL;
	if (MapNtdllFromKnownDlls(&ppNtdllBuf)) {
		if (ReplaceNtdllTxtSection(ppNtdllBuf)) {
			std::cout << "SUccess" << std::endl;
		}

	}

	return 0;
}