#pragma once

class PEParser
{
public:
	void parse(std::string path);
	~PEParser() noexcept;

	std::vector<PIMAGE_SECTION_HEADER> getSections() noexcept;
	DWORD align(DWORD size, DWORD alignment, DWORD addr);
	PIMAGE_SECTION_HEADER createSection(const char* name, DWORD size, DWORD characteristics) noexcept;

	PVOID pMapView = nullptr;
	PIMAGE_DOS_HEADER pidh = nullptr;
	PIMAGE_NT_HEADERS pinh = nullptr;
private:
	void expand(DWORD newSize);

	HANDLE hFile = nullptr;
	HANDLE hMapping = nullptr;
};

