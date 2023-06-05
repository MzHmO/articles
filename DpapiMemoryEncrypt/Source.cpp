#include <Windows.h>
#include <dpapi.h>
#include <iostream>

#pragma comment(lib, "Crypt32.lib")

int main() {
	// Data for encryption
	wchar_t name[] = L"mishahi";
	DWORD dwMod = 0;
	DWORD sizeres;
	// The memory must be a multiple of CRYPTPROTECTMEMORY_BLOCK_SIZE
	if (dwMod = sizeof(name) % CRYPTPROTECTMEMORY_BLOCK_SIZE) {
		sizeres = sizeof(name) + (CRYPTPROTECTMEMORY_BLOCK_SIZE - dwMod);
	}
	else {
		sizeres = sizeof(name);
	}

	//Reading var name from memory in var nameFromMemory
	LPWSTR nameFromMemory = (LPWSTR)LocalAlloc(LPTR, sizeres);
	SIZE_T numberreaded;

	HANDLE hProcess = GetCurrentProcess();
	ReadProcessMemory(hProcess, name, nameFromMemory, sizeres, &numberreaded);
	std::wcout << L"[+] Name From memory (before encrypt): " << nameFromMemory << std::endl;

	// Making encryption
	if (!CryptProtectMemory(name, sizeres, CRYPTPROTECTMEMORY_SAME_PROCESS)) {
		std::wcout << L"[-] Cant encrypt memory: " << GetLastError() << std::endl;
		return -1;
	}

	// Reading Encryption String. the data will not be displayed, so you have to look in the debugger
	ReadProcessMemory(hProcess, name, nameFromMemory, sizeres, &numberreaded);

	// Decrypting string
	if (!CryptUnprotectMemory(name, sizeres, CRYPTPROTECTMEMORY_SAME_PROCESS)) {

		std::wcout << L"[-] Cant decrypt memory " << GetLastError() << std::endl;
		return -1;
	}

	// Reading decrypted string
	ReadProcessMemory(hProcess, name, nameFromMemory, sizeres, &numberreaded);
	std::wcout << L"[+] Name From memory: (after decrypt) " << nameFromMemory << std::endl;
	return 0;
}