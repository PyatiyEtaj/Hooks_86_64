#pragma once

#include <iostream>
#include <Windows.h>

namespace Hooks {
	constexpr DWORD Hooks_Hooks64_BYTES_BACKUP = 32;
	constexpr DWORD Hooks_Hooks64_SAFE_BYTES_MIN = 14;
	constexpr DWORD Hooks_Hooks64_SAFE_BYTES_MAX = Hooks_Hooks64_BYTES_BACKUP - Hooks_Hooks64_SAFE_BYTES_MIN;

	class Hook64
	{
	private:
		PBYTE _originalCode = nullptr;
		PBYTE _functionToHook = nullptr;
		PBYTE _startOriginalFunction = nullptr;
		PBYTE _newFunction = 0;

		DWORD _countOfSafeBytes = Hooks_Hooks64_SAFE_BYTES_MIN;
		bool _isSetted = false;
		bool _unsetOnDie = false;

	public:
		Hook64(bool unsetOnDie)
			: _unsetOnDie(unsetOnDie)
		{}

		~Hook64()
		{
			if (_unsetOnDie)
			{
				Unset();
			}
		}

		bool Set(PBYTE functionToHook, PBYTE newFunction, DWORD countOfSafeBytes = Hooks_Hooks64_SAFE_BYTES_MIN)
		{
			CheckCountOfSafeBytes(countOfSafeBytes);

			if (!_isSetted)
			{
				Init(functionToHook, newFunction, countOfSafeBytes);
				if (SetHook(_newFunction, _functionToHook)) {
					_startOriginalFunction = CreateJmpToOririginalFuncion(_countOfSafeBytes, _functionToHook, _originalCode);
					_isSetted = true;

					return true;
				}
			}

			return false;
		}

		void Unset()
		{
			if (_isSetted)
			{
				if (_originalCode != nullptr && _functionToHook != nullptr)
				{
					memcpy_s(_functionToHook, _countOfSafeBytes, _originalCode, _countOfSafeBytes);
				}

				if (_originalCode != nullptr)
				{
					free(_originalCode);
					_originalCode = nullptr;
				}

				if (_startOriginalFunction != nullptr)
				{
					free(_startOriginalFunction);
					_startOriginalFunction = nullptr;
				}

				_isSetted = false;
			}
		}

		PBYTE GetStartOfOriginalFunction()
		{
			return _startOriginalFunction;
		}

	private:
		void CheckCountOfSafeBytes(DWORD countOfSafeBytes)
		{
			if (countOfSafeBytes > Hooks_Hooks64_SAFE_BYTES_MAX || countOfSafeBytes < Hooks_Hooks64_SAFE_BYTES_MIN)
				throw std::exception("Count of safe bytes issue");
		}

		void Init(PBYTE functionToHook, PBYTE newFunction, uint32_t countOfSafeByte)
		{
			_originalCode = (PBYTE)calloc(countOfSafeByte, sizeof(BYTE));
			_functionToHook = functionToHook;
			_newFunction = newFunction;
			_countOfSafeBytes = countOfSafeByte;
			_isSetted = false;
		}

		PBYTE CreateJmpToOririginalFuncion(uintptr_t safe, PBYTE adr, PBYTE originalCode)
		{
			PBYTE changedCode = (PBYTE)malloc(Hooks_Hooks64_BYTES_BACKUP);
			if (changedCode)
			{
				ZeroMemory(changedCode, Hooks_Hooks64_BYTES_BACKUP);
				memcpy_s(changedCode, safe, originalCode, safe);
				constexpr BYTE jmp[] = {
					0x50,                                                       // push rax         0x50
					0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rax, addr   0x48 0xB8 ....
					0xFF, 0xE0                                                  // jmp  rax         0xFF 0xE0
				};
				// 'adr + safe - 1' contains rax restoring code
				*((uintptr_t*)(jmp + 3)) = (uintptr_t)(adr + safe - 1);
				memcpy_s(changedCode + safe, sizeof(jmp), jmp, sizeof(jmp));

				DWORD temp;
				VirtualProtect(changedCode, Hooks_Hooks64_BYTES_BACKUP, PAGE_EXECUTE_READWRITE, &temp);
			}
			return changedCode;
		}

		bool SetHook(PBYTE newFunction, PBYTE functionToHook)
		{
			// check free space for 'pop rax'
			// if (*(newFunction - 1) != 0xCC) return false;

			DWORD oldProtectDip = 0;
			if (VirtualProtect(functionToHook, 16, PAGE_EXECUTE_READWRITE, &oldProtectDip))
			{
				memcpy_s(_originalCode, _countOfSafeBytes, functionToHook, _countOfSafeBytes);

				// jump with rax restoring
				constexpr BYTE jmp[] = { 
					0x50,                                                       // push rax         0x50
					0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov  rax, addr   0x48 0xB8 ....
					0xFF, 0xE0                                                  // jmp  rax         0xFF 0xE0
				};
				*((uintptr_t*)(jmp + 3)) = (uintptr_t)(newFunction - 1);

				// restore rax after jump to orig function from hooked
				*(functionToHook + _countOfSafeBytes - 1) = 0x58;   // pop rax 0x58
				// restore rax after jump to hooked func from orig
				*(newFunction - 1) = 0x58;                          // pop rax 0x58

				memcpy_s(functionToHook, sizeof(jmp), jmp, sizeof(jmp));

				return true;
			}

			return false;
		}
	};
}