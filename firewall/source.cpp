#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <netfw.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace fs = std::filesystem;

HRESULT AddFirewallRule(const std::wstring& exePath, bool addRule) {
    HRESULT hr = S_OK;
    INetFwPolicy2* pFwPolicy = NULL;
    INetFwRules* pFwRules = NULL;
    INetFwRule* pFwRule = NULL;
    BSTR bstrRuleName = SysAllocString(L"Block EXE Inbound and Outbound");
    BSTR bstrRuleDescription = SysAllocString(L"Block inbound and outbound traffic for EXE");
    BSTR bstrApplicationName = SysAllocString(exePath.c_str());

    hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        std::wcout << L"CoInitializeEx failed: " << hr << std::endl;
        goto cleanup;
    }

    hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pFwPolicy));
    if (FAILED(hr)) {
        std::wcout << L"CoCreateInstance failed: " << hr << std::endl;
        goto cleanup;
    }

    hr = pFwPolicy->get_Rules(&pFwRules);
    if (FAILED(hr)) {
        std::wcout << L"get_Rules failed: " << hr << std::endl;
        goto cleanup;
    }

    hr = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pFwRule));
    if (FAILED(hr)) {
        std::wcout << L"CoCreateInstance failed: " << hr << std::endl;
        goto cleanup;
    }

    if (addRule) {
        pFwRule->put_Name(bstrRuleName);
        pFwRule->put_Description(bstrRuleDescription);
        pFwRule->put_ApplicationName(bstrApplicationName);
        pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
        pFwRule->put_Direction(NET_FW_RULE_DIR_OUT);
        pFwRule->put_Action(NET_FW_ACTION_BLOCK);
        pFwRules->Add(pFwRule);

        std::wcout << L"[+] Firewall Outbound blocking rule Created for " << bstrApplicationName << std::endl;

        pFwRule->put_Name(bstrRuleName);
        pFwRule->put_Description(bstrRuleDescription);
        pFwRule->put_ApplicationName(bstrApplicationName);
        pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
        pFwRule->put_Direction(NET_FW_RULE_DIR_IN);
        pFwRule->put_Action(NET_FW_ACTION_BLOCK);
        pFwRules->Add(pFwRule);

        std::wcout << L"[+] Firewall Inbound blocking rule Created for " << bstrApplicationName << std::endl;
    }
    else
    {
        pFwRules->Remove(bstrRuleName);
    }

cleanup:
    if (pFwRule) 
        pFwRule->Release();
    if (pFwRules) 
        pFwRules->Release();
    if (pFwPolicy)
        pFwPolicy->Release();
    if (bstrRuleName) 
        SysFreeString(bstrRuleName);
    if (bstrRuleDescription) 
        SysFreeString(bstrRuleDescription);
    if (bstrApplicationName) 
        SysFreeString(bstrApplicationName);
    
    CoUninitialize();

    return hr;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        std::wcerr << L"Usage: FrwlBlock.exe -block|-unblock <Directory Path>\n";
        return 1;
    }

    std::wstring action = argv[1];
    std::wstring path = argv[2];

    bool shouldBlock = (action == L"-block");

    try {
        for (const auto& entry : fs::directory_iterator(path)) {
            if (entry.path().extension() == L".exe") {
                std::wcout << L"EXE found: " << entry.path().wstring() << std::endl;
                AddFirewallRule(entry.path().wstring(), shouldBlock);
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}