#pragma once
#define WIN32_NO_STATUS
#define SECURITY_WIN32
#include <Windows.h>
#include <NTSecAPI.h>
#include <iostream>
#include <sddl.h>
#include <algorithm>
#include <string>
#include <TlHelp32.h>
#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <map>
#define DEBUG
#include <locale>
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#pragma comment (lib, "Secur32.lib")
const PCWCHAR TicketFlagsToStrings[] = {
	L"name_canonicalize", L"?", L"ok_as_delegate", L"?",
	L"hw_authent", L"pre_authent", L"initial", L"renewable",
	L"invalid", L"postdated", L"may_postdate", L"proxy",
	L"proxiable", L"forwarded", L"forwardable", L"reserved",
};


const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

LSA_STRING* create_lsa_string(const char* value);
bool EnablePrivilege(PCWSTR privName, bool enable);
DWORD ImpersonateSystem();
BOOL LsaConnect(PHANDLE LsaHandle);
VOID filetimeToTime(const FILETIME* time);
VOID ParseTktFlags(ULONG flags);
DWORD ReceiveLogonInfo(HANDLE LsaHandle, LUID LogonId, ULONG kerberosAP);
ULONG GetKerberosPackage(HANDLE LsaHandle, LSA_STRING lsastr);
