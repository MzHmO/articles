#include <iostream>
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>

int main()
{
    const wchar_t* folderPath = L"C:\\Users\\Michael\\Downloads\\hiddenfolder";
    const wchar_t* trustee = L"BUILTIN\\Пользователи";
    const DWORD permissions = FILE_GENERIC_READ; // Запрет на чтение

    PACL pAcl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    PSID pSid = NULL;

    SID_NAME_USE sidType;
    DWORD sidSize = 0;
    DWORD domainSize = 0;
    LookupAccountNameW(NULL, trustee, NULL, &sidSize, NULL, &domainSize, &sidType);

    pSid = (PSID)LocalAlloc(LPTR, sidSize);
    wchar_t* domainName = (wchar_t*)LocalAlloc(LPTR, domainSize * sizeof(wchar_t));

    LookupAccountNameW(NULL, trustee, pSid, &sidSize, domainName, &domainSize, &sidType);

    EXPLICIT_ACCESSW explicitAccess;
    ZeroMemory(&explicitAccess, sizeof(EXPLICIT_ACCESSW));
    BuildExplicitAccessWithNameW(&explicitAccess, (LPWSTR)(trustee), permissions, DENY_ACCESS, NO_INHERITANCE);

    DWORD result = SetEntriesInAclW(1, &explicitAccess, NULL, &pAcl);
    if (result == ERROR_SUCCESS)
    {
        pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
        if (pSD != NULL)
        {
            if (InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
            {
                if (SetSecurityDescriptorDacl(pSD, TRUE, pAcl, FALSE))
                {
                    result = SetNamedSecurityInfoW((LPWSTR)folderPath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pAcl, NULL);
                    if (result == ERROR_SUCCESS)
                    {
                        std::wcout << L"Разрешения успешно установлены для папки " << folderPath << std::endl;
                    }
                    else
                    {
                        std::wcout << L"Не удалось установить разрешения для папки. Ошибка: " << result << std::endl;
                    }
                }
            }
        }
    }

    if (pAcl != NULL)
    {
        LocalFree(pAcl);
    }

    if (pSD != NULL)
    {
        LocalFree(pSD);
    }

    if (pSid != NULL)
    {
        LocalFree(pSid);
    }

    if (domainName != NULL)
    {
        LocalFree(domainName);
    }

    return 0;
}
