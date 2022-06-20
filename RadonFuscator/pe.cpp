#include "includes.h"

void PEParser::parse(std::string path)
{
    if (!GetFileAttributes(path.c_str()))
        throw std::runtime_error("File does not exist");

    hFile = CreateFile(path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (!hFile || hFile == INVALID_HANDLE_VALUE)
        throw std::runtime_error("CreateFile failed");

    hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);

    if (!hMapping || hMapping == INVALID_HANDLE_VALUE)
        throw std::runtime_error("CreateFileMapping failed");

    pMapView = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);

    if (!pMapView)
        throw std::runtime_error("MapViewOfFile failed");

    pidh = (PIMAGE_DOS_HEADER)pMapView;
    pinh = (PIMAGE_NT_HEADERS)((DWORD)pMapView + pidh->e_lfanew);
}

PEParser::~PEParser() noexcept
{
    if (hFile) CloseHandle(hFile);
    if (hMapping) CloseHandle(hMapping);
	if (pMapView) UnmapViewOfFile(pMapView);
}

std::vector<PIMAGE_SECTION_HEADER> PEParser::getSections() noexcept
{ 
    std::vector<PIMAGE_SECTION_HEADER> sections;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pinh);

    for (WORD i = 0; i < pinh->FileHeader.NumberOfSections; i++, section++)
    {
        sections.push_back(section);
    }
    return sections;
}

DWORD PEParser::align(DWORD size, DWORD alignment, DWORD addr)
{
    if (!(size % alignment))
        return addr + size;
    return addr + (size / alignment + 1) * alignment;
}

void PEParser::expand(DWORD newSize)
{
    if (hMapping) CloseHandle(hMapping);
    if (pMapView) UnmapViewOfFile(pMapView);

    hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, newSize, NULL);

    if (!hMapping || hMapping == INVALID_HANDLE_VALUE)
        throw std::runtime_error("CreateFileMapping failed");

    pMapView = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, newSize);

    if (!pMapView)
        throw std::runtime_error("MapViewOfFile failed");

    pidh = (PIMAGE_DOS_HEADER)pMapView;
    pinh = (PIMAGE_NT_HEADERS)((DWORD)pMapView + pidh->e_lfanew);
}

PIMAGE_SECTION_HEADER PEParser::createSection(const char* name, DWORD size, DWORD characteristics) noexcept
{
    PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((DWORD)pMapView + pidh->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    PIMAGE_SECTION_HEADER lastSection = &sections[pinh->FileHeader.NumberOfSections - 1];
    PIMAGE_SECTION_HEADER newSection = &sections[pinh->FileHeader.NumberOfSections];

    ZeroMemory(newSection, sizeof(IMAGE_SECTION_HEADER));
    CopyMemory(newSection->Name, name, 8);

    newSection->Misc.VirtualSize = align(size, pinh->OptionalHeader.SectionAlignment, 0);
    
    newSection->VirtualAddress = align(lastSection->Misc.VirtualSize, 
        pinh->OptionalHeader.SectionAlignment, 
        lastSection->VirtualAddress
    );
    
    newSection->SizeOfRawData = align(size, pinh->OptionalHeader.FileAlignment, 0);

    newSection->PointerToRawData = align(lastSection->SizeOfRawData, 
        pinh->OptionalHeader.FileAlignment, 
        lastSection->PointerToRawData
    );
   
    newSection->Characteristics = characteristics;

    pinh->OptionalHeader.SizeOfImage = newSection->VirtualAddress + newSection->SizeOfRawData;
    pinh->FileHeader.NumberOfSections++;

    expand(pinh->OptionalHeader.SizeOfImage);

    return newSection;
}