#pragma once
#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <DsGetDC.h>
#include <NTSecAPI.h>
#include <iostream>
#include <locale.h>
#include <wincrypt.h>
#include <WinBase.h>
#define DEBUG
#pragma comment (lib, "Secur32.lib")
#pragma comment (lib, "NetApi32.lib")
#pragma comment(lib,"Crypt32.lib")
DWORD TgtDeleg(LPCWSTR);