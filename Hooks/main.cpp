#include <iostream>
#include "Hook32.h"
#include "HookSetter.h"

// RELEASE
/* 6 bytes
int __stdcall PrintArgs(int argc, char** argv)
	000A1320 55                   push        ebp  
	000A1321 8B EC                mov         ebp,esp  
	000A1323 83 E4 F8             and         esp,0FFFFFFF8h
*/
DWORD CountOfSafeBytes = 6;
int __stdcall PrintArgs(int argc, char** argv)
{
	for (size_t i = 0; i < argc; i++)
	{
		std::cout << "[" << i << "] " << argv[i] << std::endl;
	}
	return 0;
}

Hooks::Hook32* hook32 = new Hooks::Hook32(true);
int Hooked_PrintArgs(int argc, char** argv)
{
	std::cout << "HOOKED" << std::endl;

	typedef int(__stdcall* orig)(int, char**);
	orig exit = (orig)(hook32->GetStartOfOriginalFunction());
	int result = exit(argc, argv);

	std::cout << "END HOOKED" << std::endl;
	return result;
}

int main(int argc, char** argv)
{
	std::cout << "STEP 1" << std::endl;
	PrintArgs(argc, argv);
	getchar();

	std::cout << "STEP 2" << std::endl;
	if (hook32->Set((PBYTE)PrintArgs, (PBYTE)Hooked_PrintArgs, CountOfSafeBytes))
	{
		PrintArgs(argc, argv);
	}
	getchar();

	std::cout << "STEP 3" << std::endl;
	delete hook32;
	PrintArgs(argc, argv);
	getchar();

	return 0;
}