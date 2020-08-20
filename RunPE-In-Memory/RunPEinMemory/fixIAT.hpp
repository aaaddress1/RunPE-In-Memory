#include <string>
#include <windows.h>
using namespace std;
char* sz_masqCmd_Ansi = NULL, *sz_masqCmd_ArgvAnsi[100] = {  };
wchar_t* sz_masqCmd_Widh = NULL, *sz_masqCmd_ArgvWidh[100] = { };
int int_masqCmd_Argc = 0;
LPWSTR hookGetCommandLineW() { return sz_masqCmd_Widh; }
LPSTR hookGetCommandLineA() { return sz_masqCmd_Ansi;  }
int __wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless) {
	*_Argc = int_masqCmd_Argc;
	*_Argv = (wchar_t **)sz_masqCmd_ArgvWidh;
	return 0;
}
int __getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless) {
	*_Argc = int_masqCmd_Argc;
	*_Argv = (char **)sz_masqCmd_ArgvAnsi;
	return 0;
}

void masqueradeCmdline(const wchar_t* cmdline) {
	if (!cmdline) return;
	auto sz_wcmdline = wstring(cmdline);

	// 
	sz_masqCmd_Widh = new wchar_t[sz_wcmdline.size() + 1];
	lstrcpyW(sz_masqCmd_Widh, sz_wcmdline.c_str());

	//
	auto k = string(sz_wcmdline.begin(), sz_wcmdline.end());
	sz_masqCmd_Ansi = new char[k.size() + 1];
	lstrcpyA(sz_masqCmd_Ansi, k.c_str());

	wchar_t** szArglist = CommandLineToArgvW(cmdline, &int_masqCmd_Argc);
	for (size_t i = 0; i < int_masqCmd_Argc; i++) {
		sz_masqCmd_ArgvWidh[i] = new wchar_t[lstrlenW(szArglist[i]) + 1];
		lstrcpyW(sz_masqCmd_ArgvWidh[i], szArglist[i]);

		auto b = string(wstring(sz_masqCmd_ArgvWidh[i]).begin(), wstring(sz_masqCmd_ArgvWidh[i]).end());
		sz_masqCmd_ArgvAnsi[i] = new char[b.size() + 1];
		lstrcpyA(sz_masqCmd_ArgvAnsi[i], b.c_str());
	}
}


bool fixIAT(PVOID modulePtr)
{
	printf("[+] Fix Import Address Table\n");
	IMAGE_DATA_DIRECTORY *importsDir = getPeDir(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (importsDir == NULL) return false;

	size_t maxSize = importsDir->Size;
	size_t impAddr = importsDir->VirtualAddress;

	IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
	size_t parsedSize = 0;

	for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);

		if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;
		LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
		printf("    [+] Import DLL: %s\n", lib_name);

		size_t call_via = lib_desc->FirstThunk;
		size_t thunk_addr = lib_desc->OriginalFirstThunk;
		if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

		size_t offsetField = 0;
		size_t offsetThunk = 0;
		while (true)
		{
			IMAGE_THUNK_DATA* fieldThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetField + call_via);
			IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetThunk + thunk_addr);
			PIMAGE_THUNK_DATA  import_Int = (PIMAGE_THUNK_DATA)(lib_desc->OriginalFirstThunk + size_t(modulePtr));

			if (import_Int->u1.Ordinal & 0x80000000) {
				//Find Ordinal Id
				size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), (char *)(orginThunk->u1.Ordinal & 0xFFFF));
				printf("        [V] API %x at %x\n", orginThunk->u1.Ordinal, addr);
				fieldThunk->u1.Function = addr;
	
			}
			
			if (fieldThunk->u1.Function == NULL) break;

			if (fieldThunk->u1.Function == orginThunk->u1.Function) {
				
				PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)(size_t(modulePtr) + orginThunk->u1.AddressOfData);
				if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) return false;

				LPSTR func_name = (LPSTR)by_name->Name;
				size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), func_name);
				printf("        [V] API %s at %x\n", func_name, addr);
				if (strcmpi(func_name, "GetCommandLineA") == 0)
					fieldThunk->u1.Function = (size_t)hookGetCommandLineA;
				else if (strcmpi(func_name, "GetCommandLineW") == 0)
					fieldThunk->u1.Function = (size_t)hookGetCommandLineW;
				else if (strcmpi(func_name, "__wgetmainargs") == 0) {
	
					fieldThunk->u1.Function = (size_t)__wgetmainargs;
				}
				else if (strcmpi(func_name, "__getmainargs") == 0) {
					fieldThunk->u1.Function = (size_t)__getmainargs;
		
				}
					
				else
					fieldThunk->u1.Function = addr;

			}
			offsetField += sizeof(IMAGE_THUNK_DATA);
			offsetThunk += sizeof(IMAGE_THUNK_DATA);
		}
	}
	return true;
}
