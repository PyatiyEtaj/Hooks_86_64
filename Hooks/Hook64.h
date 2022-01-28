#pragma once

#include <iostream>
#include <Windows.h>

namespace Hooks {
	constexpr DWORD Hooks_Hooks64_BYTES_BACKUP = 32;
	constexpr DWORD Hooks_Hooks64_SAFE_BYTES_MIN = 13;
	constexpr DWORD Hooks_Hooks64_SAFE_BYTES_MAX = Hooks_Hooks64_BYTES_BACKUP - Hooks_Hooks64_SAFE_BYTES_MIN;

	class Hook64
	{
	private:
		PBYTE _originalCode = nullptr;
		PBYTE _functionToHook = nullptr;
		PBYTE _startOriginalFunction = nullptr;
		PBYTE _newFunction = 0;

		DWORD _countOfSafeByte = Hooks_Hooks64_SAFE_BYTES_MIN;
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

		bool Set(PBYTE functionToHook, PBYTE newFunction, DWORD countOfSafeByte = Hooks_Hooks64_SAFE_BYTES_MIN)
		{
			CheckCountOfSafeBytes(countOfSafeByte);

			if (!_isSetted)
			{
				Init(functionToHook, newFunction, countOfSafeByte);
				if (SetHook(_newFunction, _functionToHook)) {
					_startOriginalFunction = CreateJmpToOririginalFuncion(_countOfSafeByte, _functionToHook, _originalCode);
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
					memcpy_s(_functionToHook, _countOfSafeByte, _originalCode, _countOfSafeByte);
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
			_countOfSafeByte = countOfSafeByte;
			_isSetted = false;
		}

		PBYTE CreateJmpToOririginalFuncion(uintptr_t safe, PBYTE adr, PBYTE originalCode)
		{
			PBYTE changedCode = (PBYTE)malloc(Hooks_Hooks64_BYTES_BACKUP);
			if (changedCode)
			{
				ZeroMemory(changedCode, Hooks_Hooks64_BYTES_BACKUP);
				memcpy_s(changedCode, safe, originalCode, safe);
				constexpr BYTE jmp[] = { 0x49, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE7 };
				*((uintptr_t*)(jmp + 2)) = (uintptr_t)(adr + safe);
				memcpy_s(changedCode + safe, sizeof(jmp), jmp, sizeof(jmp));

				DWORD temp;
				VirtualProtect(changedCode, Hooks_Hooks64_BYTES_BACKUP, PAGE_EXECUTE_READWRITE, &temp);
			}
			return changedCode;
		}

		bool SetHook(PBYTE newFunction, PBYTE functionToHook)
		{
			DWORD oldProtectDip = 0;
			if (VirtualProtect(functionToHook, 16, PAGE_EXECUTE_READWRITE, &oldProtectDip))
			{
				memcpy_s(_originalCode, _countOfSafeByte, functionToHook, _countOfSafeByte);
				constexpr BYTE jmp[] = { 0x49, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xE7 };
				*((uintptr_t*)(jmp + 2)) = (uintptr_t)newFunction;
				memcpy_s(functionToHook, sizeof(jmp), jmp, sizeof(jmp));

				return true;
			}

			return false;
		}
	};
}