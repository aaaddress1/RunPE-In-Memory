#include <windows.h>

typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY;

#define RELOC_32BIT_FIELD 3

bool applyReloc(ULONGLONG newBase, ULONGLONG oldBase, PVOID modulePtr, SIZE_T moduleSize)
{
	IMAGE_DATA_DIRECTORY* relocDir = getPeDir(modulePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (relocDir == NULL) /* Cannot relocate - application have no relocation table */
		return false;

	DWORD maxSize = relocDir->Size;
	DWORD relocAddr = relocDir->VirtualAddress;
	IMAGE_BASE_RELOCATION* reloc = NULL;

	DWORD parsedSize = 0;
	for (; parsedSize < maxSize; parsedSize += reloc->SizeOfBlock) {
		reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + DWORD(modulePtr));
		if (reloc->VirtualAddress == NULL || reloc->SizeOfBlock == 0)
			break;

		DWORD entriesNum = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		DWORD page = reloc->VirtualAddress;

		BASE_RELOCATION_ENTRY* entry = (BASE_RELOCATION_ENTRY*)(DWORD(reloc) + sizeof(IMAGE_BASE_RELOCATION));
		for (DWORD i = 0; i < entriesNum; i++) {
			DWORD offset = entry->Offset;
			DWORD type = entry->Type;
			DWORD reloc_field = page + offset;
			if (entry == NULL || type == 0)
				break;
			if (type != RELOC_32BIT_FIELD) {
				printf("    [!] Not supported relocations format at %d: %d\n", (int)i, (int)type);
				return false;
			}
			if (reloc_field >= moduleSize) {
				printf("    [-] Out of Bound Field: %lx\n", reloc_field);
				return false;
			}

			DWORD* relocateAddr = (DWORD*)(DWORD(modulePtr) + reloc_field);
			printf("    [V] Apply Reloc Field at %x\n", relocateAddr);
			(*relocateAddr) = ((*relocateAddr) - oldBase + newBase);
			entry = (BASE_RELOCATION_ENTRY*)(DWORD(entry) + sizeof(BASE_RELOCATION_ENTRY));
		}
	}
	return (parsedSize != 0);
}