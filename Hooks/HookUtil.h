#pragma once

#include <Windows.h>

// =============< MACROS >=====================
//
//#ifndef JMP32
//#define JMP32(hs)\
//		_asm { mov eax, hs }\
//		_asm { mov eax, [eax + 10h]}\
//		_asm { pop ebp }\
//		_asm { jmp eax }
//#endif
//
//#ifndef JMPPURE32
//#define JMPPURE32(hs) \
//		_asm { mov eax, hs}\
//		_asm { mov eax, [eax + 10h]}\
//		_asm { jmp eax}
//#endif
//
// ============================================

namespace Hooks
{
	template<typename T, typename ...A>
	T CallOriginalFunction(void* functionPtr, A ...args) {
		constexpr auto call_void = std::is_same_v<T, void>;
		using function = T(__stdcall*)(A...);
		const auto orig = static_cast<function>(functionPtr);
		if constexpr (call_void)
		{
			orig(args...);
		}
		else
		{
			return orig(args...);
		}

		return (T)0;
	}

	int VMTHOOK32(PDWORD* vptr, int vmtNumber, void* function)
	{
		DWORD temp;
		int originalFunction = vptr[0][vmtNumber];
		if (VirtualProtect(*vptr, 4, PAGE_EXECUTE_READWRITE, &temp)) {
			vptr[0][vmtNumber] = (DWORD)function;
		}
		return originalFunction;
	}

	int VMTHOOK32(PDWORD vptr, int vmtNumber, void* function)
	{
		DWORD temp;
		int originalFunction = vptr[vmtNumber];
		if (VirtualProtect(vptr, 4, PAGE_EXECUTE_READWRITE, &temp)) {
			vptr[vmtNumber] = (DWORD)function;
		}
		return originalFunction;
	}

	bool DetourFunc32(PBYTE adrOld, PBYTE adrNew, bool replaceByJmpE9 = false)
	{
		if (adrOld == nullptr || adrNew == nullptr)
		{
			return false;
		}

		DWORD off = (DWORD)adrNew - (DWORD)adrOld - 5;
		if (replaceByJmpE9)
		{
			memcpy_s((void*)(adrOld), 1, "\xE9", 1);
		}
		memcpy_s((void*)(adrOld + 1), 4, (void*)&off, 4);

		return true;
	}
}