#include "pch.h"
#include <Windows.h>
#include <httpserv.h>
#include "classes.h"

CHttpModuleFactory * pFactory = NULL;


__declspec(dllexport) HRESULT __stdcall RegisterModule(DWORD dwServerVersion, IHttpModuleRegistrationInfo * pModuleInfo, IHttpServer * pHttpServer)
{
    OutputDebugString(L"RegisterModule");
    pFactory = new CHttpModuleFactory(); 

    HRESULT hr = pModuleInfo->SetRequestNotifications(pFactory, RQ_SEND_RESPONSE, 0);
    
    return hr;
}

