#include <Windows.h>
#include <algorithm>
#include <string>
#include <wininet.h>
#include <iostream>
#include <winternl.h>
#pragma comment(lib, "Wininet.lib")

#define FIXED_URL	L"https://msdl.microsoft.com/download/symbols/ntdll.dll/"

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

BOOL GetPayloadFromUrl(IN LPCWSTR szUrl, OUT PVOID* pNtdllBuffer, OUT PSIZE_T sNtdllSize) {

	BOOL		bSTATE = TRUE;

	HINTERNET	hInternet = NULL,
		hInternetFile = NULL;

	DWORD		dwBytesRead = NULL;

	SIZE_T		sSize = NULL; 	 			

	PBYTE		pBytes = NULL,					
		pTmpBytes = NULL;				

	hInternet = InternetOpenW(L"info", NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	
	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		
		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		
		sSize += dwBytesRead;

	
		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

	
		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

		
		memset(pTmpBytes, '\0', dwBytesRead);

		
		if (dwBytesRead < 1024) {
			break;
		}

		
	}



	*pNtdllBuffer = pBytes;
	*sNtdllSize = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);     
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);    
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);  
	if (pTmpBytes)
		LocalFree(pTmpBytes);                  
	return bSTATE;
}


BOOL ReadNtdllFromServer(OUT PVOID* ppNtdllBuf) {

	PBYTE      pNtdllModule = (PBYTE)FetchLocalNtdllBaseAddress();
	PVOID      pNtdllBuffer = NULL;
	SIZE_T     sNtdllSize = NULL;
	WCHAR      szFullUrl[MAX_PATH] = { 0 };

	
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pNtdllModule;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;


	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pNtdllModule + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	
	wsprintfW(szFullUrl, L"%s%0.8X%0.4X/ntdll.dll", FIXED_URL, pImgNtHdrs->FileHeader.TimeDateStamp, pImgNtHdrs->OptionalHeader.SizeOfImage);

	
	if (!GetPayloadFromUrl(szFullUrl, &pNtdllBuffer, &sNtdllSize))
		return FALSE;



	*ppNtdllBuf = pNtdllBuffer;

	return TRUE;
}

BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll) {

	PVOID			   pLocalNtdll = (PVOID)FetchLocalNtdllBaseAddress();


	PIMAGE_DOS_HEADER	pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
	if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;


	PIMAGE_NT_HEADERS 	pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
	if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;


	PVOID     pLocalNtdllTxt = NULL, 
		pRemoteNtdllTxt = NULL; 
	SIZE_T    sNtdllTxtSize = NULL; 


	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

	for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {

		//if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
		if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {

			pLocalNtdllTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
			pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + 1024);
			sNtdllTxtSize = pSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}


	if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize)
		return FALSE;


	if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt) {
	
		pRemoteNtdllTxt = (PVOID)((char*)pRemoteNtdllTxt + 3072);

		if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt)
			return FALSE;
	}

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
	PVOID ntdllbuf = NULL;
	if (ReadNtdllFromServer(&ntdllbuf)) {
		if (ReplaceNtdllTxtSection(ntdllbuf)) {
			std::cout << "success" << std::endl;
		}
	}

	return 0;
}