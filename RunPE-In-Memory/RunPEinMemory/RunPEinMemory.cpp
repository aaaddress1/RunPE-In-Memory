#include "stdafx.h"
#include <Windows.h>
#include "peBase.hpp"
#include "fixIAT.hpp"
#include "fixReloc.hpp"

bool peLoader(const char *exePath, const wchar_t* cmdline)
{
	LONGLONG fileSize = -1;
	BYTE *data = MapFileToMemory(exePath, fileSize);
	BYTE* pImageBase = NULL;
	LPVOID preferAddr = 0;
	IMAGE_NT_HEADERS *ntHeader = (IMAGE_NT_HEADERS *)getNtHdrs(data);
	if (!ntHeader) 
	{
		printf("[+] File %s isn't a PE file.", exePath);
		return false;
	}

	IMAGE_DATA_DIRECTORY* relocDir = getPeDir(data, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;
	printf("[+] Exe File Prefer Image Base at %x\n", preferAddr);

	HMODULE dll = LoadLibraryA("ntdll.dll");
	((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll, "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);
	
	pImageBase = (BYTE *)VirtualAlloc(preferAddr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pImageBase && !relocDir)
	{
		printf("[-] Allocate Image Base At %x Failure.\n", preferAddr);
		return false;
	}
	if (!pImageBase && relocDir)
	{
		printf("[+] Try to Allocate Memory for New Image Base\n");
		pImageBase = (BYTE *)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pImageBase)
		{
			printf("[-] Allocate Memory For Image Base Failure.\n");
			return false;
		}
	}
	
	puts("[+] Mapping Section ...");
	ntHeader->OptionalHeader.ImageBase = (size_t)pImageBase;
	memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);

	IMAGE_SECTION_HEADER * SectionHeaderArr = (IMAGE_SECTION_HEADER *)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		printf("    [+] Mapping Section %s\n", SectionHeaderArr[i].Name);
		memcpy
		(
			LPVOID(size_t(pImageBase) + SectionHeaderArr[i].VirtualAddress),
			LPVOID(size_t(data) + SectionHeaderArr[i].PointerToRawData),
			SectionHeaderArr[i].SizeOfRawData
		);
	}

	// for demo usage: 
	// masqueradeCmdline(L"C:\\Windows\\RunPE_In_Memory.exe Demo by aaaddress1");
	masqueradeCmdline(cmdline);
	fixIAT(pImageBase);

	if (pImageBase != preferAddr) 
		if (applyReloc((size_t)pImageBase, (size_t)preferAddr, pImageBase, ntHeader->OptionalHeader.SizeOfImage))
		puts("[+] Relocation Fixed.");
	size_t retAddr = (size_t)(pImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;
	printf("Run Exe Module: %s\n", exePath);

	((void(*)())retAddr)();
}

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		printf("Usage: %s [Exe Path]", strrchr(argv[0], '\\') ? strrchr(argv[0], '\\') + 1 : argv[0]);
		getchar();
		return 0;
	}

	peLoader(argv[1], NULL);
	getchar();
    return 0;
}

