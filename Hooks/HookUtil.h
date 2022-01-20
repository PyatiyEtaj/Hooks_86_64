#pragma once

#include <Windows.h>

// =============< MACROS >=====================
#ifndef JMP32
#define JMP32(hs)\
		_asm { mov eax, hs }\
		_asm { mov eax, [eax + 10h]}\
		_asm { pop ebp }\
		_asm { jmp eax }
#endif

#ifndef JMPPURE32
#define JMPPURE32(hs) \
		_asm { mov eax, hs}\
		_asm { mov eax, [eax + 10h]}\
		_asm { jmp eax}
#endif

#define GO_TO_ORIGINAL_VOID_FUNCTION(type, hook32, ...) \
	type exit = (type)(hook32->GetStartOfOriginalFunction()); \
	exit(__VA_ARGS__);


#define GO_TO_ORIGINAL_FUNCTION(type, hook32, ...) \
	type exit = (type)(hook32->GetStartOfOriginalFunction()); \
	return exit(__VA_ARGS__);

#define GO_TO_ORIGINAL_VOID_FUNCTION2(type, hook32, ...) ((type)(hook32->GetStartOfOriginalFunction()))(__VA_ARGS__)

// ============================================

namespace Hooks
{
	int VMTHOOK32(int** vptr, int vmtNumber, void* function)
	{
		DWORD temp;
		int originalFunction = vptr[0][vmtNumber];
		if (VirtualProtect(*vptr, 4, PAGE_EXECUTE_READWRITE, &temp)) {
			vptr[0][vmtNumber] = (int)function;
		}
		return originalFunction;
	}

	int VMTHOOK32(PDWORD vptr, int vmtNumber, void* function)
	{
		DWORD temp;
		int originalFunction = vptr[vmtNumber];
		if (VirtualProtect(vptr, 4, PAGE_EXECUTE_READWRITE, &temp)) {
			vptr[vmtNumber] = (int)function;
		}
		return originalFunction;
	}
}