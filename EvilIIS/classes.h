#pragma once

#include <Windows.h>
#include <iostream>
#include <httpserv.h>
class CChildHttpModule : public CHttpModule
{
public:
	REQUEST_NOTIFICATION_STATUS OnSendResponse(IN IHttpContext* pHttpContext, IN ISendResponseProvider* pProviderss);
};


class CHttpModuleFactory : public IHttpModuleFactory
{
public:
	HRESULT GetHttpModule(CHttpModule** ppModule, IModuleAllocator* pModuleAlloc);

	void Terminate();
};


