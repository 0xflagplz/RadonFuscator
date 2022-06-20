#include "includes.h"

#define EMIT(c) __asm _emit c

#define COMPARE(str1, str2) \
    __asm push str1 \
    __asm call stringLength \
    __asm push eax \
    __asm push str1 \
    __asm push str2 \
    __asm call stringEquality

#pragma code_seg(".radon")
__declspec(naked) void stub()
{
    __asm {
        pushad // Save context of entry point
        push ebp // Set up stack frame
        mov ebp, esp
        sub esp, 0x200 // Space for local variables
    }

    DWORD currentImageBase;
    DWORD ntdllImageBase;
    DWORD kernelImageBase;

    __asm {
        call getModuleList
        mov ebx, eax

        push ebx
        push 0
        call getBaseAddress
        mov currentImageBase, eax

        push ebx
        push 1
        call getBaseAddress
        mov ntdllImageBase, eax

        push ebx
        push 2
        call getBaseAddress
        mov kernelImageBase, eax
    }

    __asm {
        call getModuleList
        mov ebx, [ebx + 0x20] // SizeOfImage

        mov eax, fs : [0x30] // Get PEB
        mov[eax + 0x8], ebx // Set ImageBaseAddress to SizeOfImage (genius)
    }

    __asm {
        push kernelImageBase
        push ntdllImageBase
        call hideFromDebugger
    }

    __asm {
        push kernelImageBase
        push currentImageBase
        call decryptSections
    }

    __asm {
        mov eax, currentImageBase
        add eax, 0xAAAAAAAA // OEP
        mov esp, ebp
        mov[esp + 0x20], eax // Store OEP in EAX through ESP to preserve across popad
        pop ebp
        popad
        jmp eax // Jump to OEP
    }

    __asm {
    getModuleList:
        mov eax, fs : [0x30] // Get PEB
        mov eax, [eax + 0xC] // Get LDR
        mov eax, [eax + 0xC] // Get InLoadOrderModuleList
        retn
    }

    __asm {
    getBaseAddress:
        push ebp
        mov ebp, esp

        cmp [ebp + 0x8], 0x0 // If the parameter is zero then return first module
        je done

        mov ecx, [ebp + 0x8]
        mov eax, [ebp + 0xC]

        traverseList:
            mov eax, [eax] // Goto next entry
        loop traverseList

        done:
            mov eax, [eax + 0x18] // Get DllBase
            mov esp, ebp
            pop ebp
            ret
    }

    // int stringLength(char* str)
    __asm {
    stringLength:
        push ebp
        mov ebp, esp
        mov edi, [ebp + 0x8] // String to get length from
        mov eax, 0x0
        countingLoop:
            cmp byte ptr[edi], 0x0
            je stringDone
            inc edi
            inc eax // Increment result length
            jmp countingLoop
        stringDone:
            mov esp, ebp
            pop ebp
            retn
    }

    // int stringEquality(char* str1, char* str2, int length)
    __asm {
    stringEquality:
        push ebp
        mov ebp, esp
        mov eax, 0x0 // Assume unequal
        cld
        mov esi, [ebp + 0x8] // First string
        mov edi, [ebp + 0xC] // Second string
        mov ecx, [ebp + 0x10] // First string length
        repe cmpsb
        jne end
        mov eax, 0x1
    end:
        mov esp, ebp
        pop ebp
        ret
    }

// FARPROC getProcAddr(HMODULE hModule, LPCSTR lpProcName)
getProcAddr:
    {
        __asm {
            push ebp // Set up stack frame
            mov ebp, esp
            sub esp, 0x200 // Space for local variables
        }

        PIMAGE_DOS_HEADER pidh;

        // Initializations
        __asm {
            mov eax, [ebp + 0x8];
            mov pidh, eax;
        }

        PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)pidh + pidh->e_lfanew);

        PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)pidh +
            pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        PDWORD nameTable = (PDWORD)((DWORD_PTR)pidh + pied->AddressOfNames);

        FARPROC functionAddr;

        for (DWORD i = 0; i < pied->NumberOfNames; i++)
        {
            char* functionName = (char*)((DWORD_PTR)pidh + nameTable[i]);

            int equal;
            COMPARE([ebp + 0xC], functionName);
            __asm mov equal, eax

            if (equal)
            {
                PWORD ordinalTable = (PWORD)((DWORD_PTR)pidh + pied->AddressOfNameOrdinals);
                PDWORD functionTable = (PDWORD)((DWORD_PTR)pidh + pied->AddressOfFunctions);
                functionAddr = (FARPROC)((DWORD_PTR)pidh + functionTable[ordinalTable[i]]);
                break;
            }
        }

        __asm {
            mov eax, functionAddr
            mov esp, ebp
            pop ebp
            ret
        }
    }

// void hideFromDebugger(DWORD ntdllImageBase, DWORD kernelImageBase)
hideFromDebugger:
    {
        __asm {
            push ebp
            mov ebp, esp
            sub esp, 0x200
        }

        char* szNtSetInformationThread;
        char* szGetCurrentThread;

        // String initializations
        __asm {
            call callbackNtSetInformationThread
            EMIT('N')EMIT('t')EMIT('S')EMIT('e')EMIT('t')
            EMIT('I')EMIT('n')EMIT('f')EMIT('o')EMIT('r')EMIT('m')EMIT('a')EMIT('t')EMIT('i')EMIT('o')EMIT('n')
            EMIT('T')EMIT('h')EMIT('r')EMIT('e')EMIT('a')EMIT('d')EMIT(0)
            callbackNtSetInformationThread:
                pop esi
                mov szNtSetInformationThread, esi

            call callbackGetCurrentThread
            EMIT('G')EMIT('e')EMIT('t')EMIT('C')EMIT('u')EMIT('r')EMIT('r')EMIT('e')EMIT('n')EMIT('t')
            EMIT('T')EMIT('h')EMIT('r')EMIT('e')EMIT('a')EMIT('d')EMIT(0)
            callbackGetCurrentThread:
                pop esi
                mov szGetCurrentThread, esi
        }

        typedef NTSTATUS(NTAPI* f_NtSetInformationThread)(HANDLE ThreadHandle, ULONG ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
        f_NtSetInformationThread pNtSetInformationThread;

        typedef HANDLE(WINAPI* f_GetCurrentThread)();
        f_GetCurrentThread pGetCurrentThread;

        // Initializations
        __asm {
            push szNtSetInformationThread // NtSetInformationThread
            push[ebp + 0x8] // ntdll DllBase
            call getProcAddr
            mov pNtSetInformationThread, eax

            push szGetCurrentThread // GetCurrentThread
            push[ebp + 0xC] // kernel32 DllBase
            call getProcAddr
            mov pGetCurrentThread, eax
        }

        // Hide thread from debuggers
        pNtSetInformationThread(pGetCurrentThread(), 0x11, NULL, 0);

        __asm {
            mov esp, ebp
            pop ebp
            ret
        }
    }

// void decryptSections(DWORD currentImageBase, DWORD kernelImageBase)
decryptSections:
    {
        __asm {
            push ebp // Set up stack frame
            mov ebp, esp
            sub esp, 0x200 // Space for local variables
        }

        char* szNewSection;
        char* szRsrc;
        char* szRdata;
        char* szVirtualProtect;

        // String initializations
        __asm {
            call callbackNewSection
            EMIT('.')EMIT('r')EMIT('a')EMIT('d')EMIT('o')EMIT('n')EMIT(0)
            callbackNewSection:
                pop esi
                mov szNewSection, esi

            call callbackRsrc
            EMIT('.')EMIT('r')EMIT('s')EMIT('r')EMIT('c')EMIT(0)
            callbackRsrc:
                pop esi
                mov szRsrc, esi
            
            call callbackRdata
            EMIT('.')EMIT('r')EMIT('d')EMIT('a')EMIT('t')EMIT('a')EMIT(0)
            callbackRdata:
                pop esi
                mov szRdata, esi

            call callbackVirtualProtect
            EMIT('V')EMIT('i')EMIT('r')EMIT('t')EMIT('u')EMIT('a')EMIT('l')
            EMIT('P')EMIT('r')EMIT('o')EMIT('t')EMIT('e')EMIT('c')EMIT('t')EMIT(0)
            callbackVirtualProtect:
                pop esi
                mov szVirtualProtect, esi
        }

        PIMAGE_DOS_HEADER pidh;

        typedef BOOL (WINAPI* f_VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
        f_VirtualProtect pVirtualProtect;

        // Initializations
        __asm {
            mov eax, [ebp + 0x8]
            mov pidh, eax

            push szVirtualProtect // VirtualProtect
            push[ebp + 0xC] // kernel32 DllBase
            call getProcAddr
            mov pVirtualProtect, eax
        }

        PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)pidh + pidh->e_lfanew);

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pinh);

        DWORD oldProtect;
        pVirtualProtect(pidh, pinh->FileHeader.SizeOfOptionalHeader, PAGE_READWRITE, &oldProtect);

        for (WORD i = 0; i < pinh->FileHeader.SizeOfOptionalHeader; i++)
            *(BYTE*)((DWORD_PTR)pidh + i) = 0;

        pVirtualProtect(pidh, pinh->FileHeader.SizeOfOptionalHeader, oldProtect, &oldProtect);

        for (WORD i = 0; i < pinh->FileHeader.NumberOfSections; i++)
        {
            int equal;
            COMPARE(szNewSection, section);
            __asm mov equal, eax
            COMPARE(szRsrc, section);
            __asm add equal, eax
            COMPARE(szRdata, section);
            __asm add equal, eax

            if (!equal)
            {
                DWORD address = (DWORD_PTR)pidh + section->VirtualAddress;

                DWORD oldProtect;
                pVirtualProtect((LPVOID)address, section->SizeOfRawData, PAGE_READWRITE, &oldProtect);

                int key = 0xAAAAAAAA;
                int hash = 0xAAAAAAAA;

                for (int j = 0; j < sizeof(section->Name); j++)
                    hash = (hash ^ section->Name[j]) * key;
                hash += hash << 12;
                hash -= hash >> 6;

                for (DWORD j = 0; j < section->SizeOfRawData; j++)
                    *(BYTE*)(address + j) ^= hash;

                pVirtualProtect((LPVOID)address, section->SizeOfRawData, oldProtect, &oldProtect);
            }
            section++;
        }

        __asm {
            mov esp, ebp
            pop ebp
            ret
        }
    }

    // Signature
    __asm _emit 0xCC
    __asm _emit 0xCC
    __asm _emit 0xCC
    __asm _emit 0xCC
}

void encryptSection(PEParser* parser, PIMAGE_SECTION_HEADER section, DWORD key, DWORD hash)
{
    for (int j = 0; j < sizeof(section->Name); j++)
        hash = (hash ^ section->Name[j]) * key;
    hash += hash << 12;
    hash -= hash >> 6;

    DWORD address = ((DWORD_PTR)parser->pMapView + section->PointerToRawData);

    for (DWORD i = 0; i < section->SizeOfRawData; i++)
        *(BYTE*)(address + i) ^= hash;
}

DWORD getStubSize(void* stubAddr)
{
    DWORD i = 0;
    for (i = 0; *(UINT32*)((BYTE*)stubAddr + i) != 0xCCCCCCCC; i++);
    return i;
}

DWORD generateKey()
{
    std::random_device rd;
    std::default_random_engine generator(rd());
    std::uniform_int_distribution<long unsigned> distribution(0, 0xFFFFFFFF);
    return distribution(generator);
}

bool patchBytes(DWORD dstAddress, DWORD size, LPVOID srcAddress, UINT32 signature)
{
    for (DWORD i = 0; i < size; ++i)
    {
        if (*(UINT32*)(dstAddress + i) == signature)
        {
            memcpy((PVOID)(dstAddress + i), srcAddress, sizeof(DWORD));
            return true;
        }
    }
    return false;
}

int main(int argc, char** argv)
{
    std::string path;

    if (argc > 1)
    {
        path = argv[1];
    }
    else
    {
        std::cout << "Enter executable to pack: ";
        std::getline(std::cin, path);
    }

    path.erase(std::remove(path.begin(), path.end(), '"'), path.end());

    std::string savePath = path.substr(0, path.find_last_of(".")) + ".packed" +
        path.substr(path.find_last_of("."), path.length() - path.find_last_of("."));

    if (std::filesystem::exists(savePath))
        DeleteFile(savePath.c_str());

    if (!CopyFile(path.c_str(), savePath.c_str(), true))
    {
        throw std::runtime_error("CopyFile failed");
    }

    PEParser* parser = new PEParser();

    parser->parse(savePath);

    std::vector<PIMAGE_SECTION_HEADER> sections = parser->getSections();

    std::vector<const char*> exclude = {
        ".rsrc",
        ".rdata",
        ".tls"
    };

    DWORD key = generateKey();
    DWORD hash = generateKey();

    std::cout << std::format("Generated encryption key: {}", key) << std::endl;
    std::cout << std::format("Generated encryption key: {}", hash) << std::endl;

    for (size_t i = 0; i < sections.size(); i++)
    {
        int equal = 1;

        for (size_t j = 0; j < exclude.size(); j++)
            equal &= strcmp((char*)sections[i]->Name, exclude[j]);

        if (equal)
        {
            std::cout << std::format("Encrypting section: {}", (char*)sections[i]->Name) << std::endl;
            encryptSection(parser, sections[i], key, hash);
        }
    }

    PVOID stubAddress = stub;
    DWORD stubSize = getStubSize(stubAddress);

    PIMAGE_SECTION_HEADER newSection = parser->createSection(".radon", stubSize, 
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);

    std::cout << std::format("Created PE section: {}", (char*)newSection->Name) << std::endl;

    DWORD dstAddress = (DWORD_PTR)parser->pMapView + newSection->PointerToRawData;

    std::cout << std::format("Copying stub to {}", (char*)newSection->Name) << std::endl;

    memcpy((PVOID)dstAddress, stubAddress, stubSize);

    DWORD oep = parser->pinh->OptionalHeader.AddressOfEntryPoint;
    parser->pinh->OptionalHeader.AddressOfEntryPoint = newSection->VirtualAddress;

    std::cout << std::format("Changed EntryPoint to {}", parser->pinh->OptionalHeader.AddressOfEntryPoint) << std::endl;

    std::cout << "Patching bytes..." << std::endl;

    patchBytes(dstAddress, newSection->SizeOfRawData, &oep, 0xAAAAAAAA);
    patchBytes(dstAddress, newSection->SizeOfRawData, &key, 0xAAAAAAAA);
    patchBytes(dstAddress, newSection->SizeOfRawData, &hash, 0xAAAAAAAA);

    std::cout << std::format("Protected executable saved to {}", savePath) << std::endl;
}