// gcc PoC.cpp -Wl,--dynamicbase,--export-all-symbols -Wl,-- image-base=0xff00000
#include <stdio.h>
#include <windows.h>
int main(int argc, char **argv)
{
	printf("GetCommandLine() = \"%s\"\n", GetCommandLineA());
	for (int i = 0; i < argc; i++)
		printf("argv[%i] = %s\n", i, argv[i]);
}
