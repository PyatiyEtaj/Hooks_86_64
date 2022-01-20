#pragma once

#include <iostream>
#include <Windows.h>

namespace Hooks {
	const DWORD Hooks_Hooks32_BYTES_BACKUP = 24;
	const DWORD Hooks_Hooks32_SAFE_BYTES_MIN = 5;
	const DWORD Hooks_Hooks32_SAFE_BYTES_MAX = 19;

	class Hook32
	{
	private:

		PBYTE _originalCode = nullptr;
		PBYTE _myCode = nullptr;
		PBYTE _functionToHook = nullptr;
		PBYTE _startOriginalFunction = nullptr;
		PBYTE _newFunction = 0;

		DWORD _countOfSafeByte = Hooks_Hooks32_SAFE_BYTES_MIN;
		bool _isSetted = false;
		bool _unsetOnDie = false;

	public:
		Hook32(bool unsetOnDie)
			: _unsetOnDie(unsetOnDie)
		{}

		~Hook32()
		{
			if (_unsetOnDie)
			{
				Unset();
			}
		}

		bool Set(PBYTE functionToHook, PBYTE newFunction, DWORD countOfSafeByte = Hooks_Hooks32_SAFE_BYTES_MIN)
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

				if (_myCode != nullptr)
				{
					free(_myCode);
					_myCode = nullptr;
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
			if (countOfSafeBytes > Hooks_Hooks32_SAFE_BYTES_MAX || countOfSafeBytes < Hooks_Hooks32_SAFE_BYTES_MIN)
				throw std::exception("countOfSafeBytes");
		}

		void Init(PBYTE functionToHook, PBYTE newFunction, DWORD countOfSafeByte)
		{
			_originalCode = (PBYTE)calloc(countOfSafeByte, sizeof(BYTE));
			_myCode = (PBYTE)calloc(countOfSafeByte, sizeof(BYTE));
			_functionToHook = functionToHook;
			_newFunction = newFunction;
			_countOfSafeByte = countOfSafeByte;
			_isSetted = false;
		}

		PBYTE CreateJmpToOririginalFuncion(DWORD safe, PBYTE adr, BYTE* originalCode)
		{
			PBYTE changedCode = (PBYTE)malloc(Hooks_Hooks32_BYTES_BACKUP);
			if (changedCode)
			{
				ZeroMemory(changedCode, Hooks_Hooks32_BYTES_BACKUP);
				memcpy_s(changedCode, safe, originalCode, safe);
				changedCode[safe] = 0xE9;
				DWORD addr = (DWORD)(adr + safe) - (DWORD)(changedCode + safe) - 5;
				memcpy_s(changedCode + (safe + 1), 4, (void*)&addr, 4);
				DWORD temp;
				VirtualProtect(changedCode, Hooks_Hooks32_BYTES_BACKUP, PAGE_EXECUTE_READWRITE, &temp);
			}
			return changedCode;
		}

		bool SetHook(PBYTE newFunction, PBYTE functionToHook)
		{
			DWORD oldProtectDip = 0;
			if (VirtualProtect((PBYTE)functionToHook, 8, PAGE_EXECUTE_READWRITE, &oldProtectDip))
			{
				memcpy_s(_originalCode, _countOfSafeByte, functionToHook, _countOfSafeByte);
				_myCode[0] = 0xE9;
				DWORD addr = (DWORD)newFunction - (DWORD)functionToHook - 5;
				memcpy_s(_myCode + 1, 4, (void*)&addr, 4);
				memcpy_s(functionToHook, 5, _myCode, 5);
				return true;
			}

			return false;
		}
	};
}