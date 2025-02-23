#include <windows.h>
#include <Dbghelp.h>
#include <iostream>
#include <vector>
#include <mutex>

std::vector<BYTE> GetFunctionBytes() {
  
    return { 0x53, 0x56, 0x57, 0x48, 0x81, 0xEC, 0xB0, 0x01, 0x00, 0x00 };
}

std::mutex mtx;
uintptr_t foundAddress = 0; 

void ScanMemory(HANDLE hProcess, const std::vector<BYTE>& pattern, uintptr_t start, uintptr_t end) {
    for (uintptr_t address = start; address < end; address += 0x1000) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READ)) {
                std::vector<BYTE> buffer(mbi.RegionSize);
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, (LPCVOID)address, buffer.data(), mbi.RegionSize, &bytesRead)) {
                    for (size_t i = 0; i < bytesRead - pattern.size(); i++) {
                        if (std::equal(pattern.begin(), pattern.end(), buffer.begin() + i)) {
                            std::lock_guard<std::mutex> lock(mtx);
                            foundAddress = address + i;
                            return; 
                        }
                    }
                }
            }
        }
    }
}

uintptr_t FindFunction(HANDLE hProcess, const std::vector<BYTE>& pattern, uintptr_t baseAddress) {
    uintptr_t scanStart = baseAddress;
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t scanEnd = (uintptr_t)sysInfo.lpMaximumApplicationAddress;

    const int numThreads = 4; 
    std::vector<std::thread> threads;

    uintptr_t rangeSize = scanEnd - scanStart;
    uintptr_t chunkSize = rangeSize / numThreads;

    for (int i = 0; i < numThreads; ++i) {
        uintptr_t start = scanStart + i * chunkSize;
        uintptr_t end = (i == numThreads - 1) ? scanEnd : start + chunkSize;
        threads.emplace_back(ScanMemory, hProcess, pattern, start, end);
    }

    for (auto& thread : threads) {
        thread.join();
    }

    return foundAddress; 
}

typedef int (WINAPI* DphCommitMemoryFromPageHeapFunc)(
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG Protect
	);

int main()
{
	HMODULE hModule = NULL;

	hModule = LoadLibraryA("verifier.dll");
	DphCommitMemoryFromPageHeapFunc DphCommitMemoryFromPageHeapWPtr = (DphCommitMemoryFromPageHeapFunc)(FindFunction(GetCurrentProcess(), GetFunctionBytes(), (uintptr_t)hModule));
	SIZE_T size = 0xABCD;
    LPVOID addr = nullptr;
	NTSTATUS err = DphCommitMemoryFromPageHeapWPtr(&addr, &size, PAGE_EXECUTE);
	std::wcout << err << std::endl;

	return 0;
}