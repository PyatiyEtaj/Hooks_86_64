#include <iostream>
#include "HookUtil.h"
#include "Hook64.h"
#include "Hook32.h"

#if _WIN64
/* x64
 * 15 bytes
int __stdcall PrintArgs(int argc, char** argv)
	00007FF6FCEF1390 48 89 5C 24 08       mov         qword ptr [rsp+8],rbx  
	00007FF6FCEF1395 48 89 74 24 10       mov         qword ptr [rsp+10h],rsi  
	00007FF6FCEF139A 57                   push        rdi  
	00007FF6FCEF139B 48 83 EC 20          sub         rsp,20h
*/
DWORD CountOfSafeBytes = 15;
#elif _WIN32
/* x86
 * 6 bytes
int __stdcall PrintArgs(int argc, char** argv)
	000A1320 55                   push        ebp  
	000A1321 8B EC                mov         ebp,esp  
	000A1323 83 E4 F8             and         esp,0FFFFFFF8h
*/
DWORD CountOfSafeBytes = 6;
#endif
int PrintArgs(int argc, char** argv)
{
	for (int i = 0; i < argc; i++)
	{
		std::cout << "[" << i << "] " << argv[i] << std::endl;
	}
	return 1488;
}

#if _WIN64
Hooks::Hook64* hook64 = new Hooks::Hook64(true);
int Hooked64_PrintArgs(int argc, char** argv)
{
	std::cout << "HOOKED64" << std::endl;

	// C99 style
	/*typedef int(* orig)(int, char**);
	orig exit = (orig)(hook64->GetStartOfOriginalFunction());
	int result = exit(argc, argv);*/
	// C++17 style
	const auto result = Hooks::CallOriginalFunction<int>((void*)hook64->GetStartOfOriginalFunction(), argc, argv);

	std::cout << "END HOOKED64 [" << result << "]" << std::endl;
	return result;
}
#elif _WIN32
Hooks::Hook32* hook32 = new Hooks::Hook32(true);
int Hooked32_PrintArgs(int argc, char** argv)
{
	std::cout << "HOOKED32" << std::endl;

	// C99 style
	/*typedef int(__stdcall* orig)(int, char**);
	orig exit = (orig)(hook32->GetStartOfOriginalFunction());
	int result = exit(argc, argv);*/
	// C++17 style
	const int result = Hooks::CallOriginalFunction<int>((void*)hook32->GetStartOfOriginalFunction(), argc, argv);

	std::cout << "END HOOKED32 [" << result << "]" << std::endl;
	return result;
}
#endif

int _cdecl main(int argc, char** argv)
{
	std::cout << "STEP 1" << std::endl;
	PrintArgs(argc, argv);
		
#if _WIN64
	std::cout << std::endl << "[x64] STEP 2" << std::endl;
	if (hook64->Set((PBYTE)PrintArgs, (PBYTE)Hooked64_PrintArgs, CountOfSafeBytes))
	{
		PrintArgs(argc, argv);
	}
#elif _WIN32
	std::cout << std::endl << "[x86] STEP 2" << std::endl;
	if (hook32->Set((PBYTE)PrintArgs, (PBYTE)Hooked32_PrintArgs, CountOfSafeBytes))
	{
		PrintArgs(argc, argv);
	}	
#endif

	std::cout << std::endl << "STEP 3" << std::endl;
#if _WIN64
	delete hook64;
#elif _WIN32
	delete hook32;
#endif
	PrintArgs(argc, argv);

	return 0;
}