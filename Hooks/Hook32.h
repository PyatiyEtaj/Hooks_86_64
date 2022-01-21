#pragma once

#include <iostream>
#include <Windows.h>

namespace Hooks {
	constexpr DWORD Hooks_Hooks32_BYTES_BACKUP = 24;
	constexpr DWORD Hooks_Hooks32_SAFE_BYTES_MIN = 1 + sizeof(DWORD);
	constexpr DWORD Hooks_Hooks32_SAFE_BYTES_MAX = Hooks_Hooks32_BYTES_BACKUP- Hooks_Hooks32_SAFE_BYTES_MIN;

	class Hook32
	{
	private:
		/*
		* jmp relative_adress_to_function;
		*/
		const DWORD SIZE_OF_INSTRUCTION = Hooks_Hooks32_SAFE_BYTES_MIN;

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
				throw std::exception("Count of safe bytes issue");
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
				DWORD relative = (DWORD)(adr + safe) - (DWORD)(changedCode + safe) - SIZE_OF_INSTRUCTION;
				memcpy_s(changedCode + (safe + 1), 4, (void*)&relative, 4);
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
				DWORD relative = (DWORD)newFunction - (DWORD)functionToHook - SIZE_OF_INSTRUCTION;
				memcpy_s(_myCode + 1, 4, (void*)&relative, 4);
				memcpy_s(functionToHook, SIZE_OF_INSTRUCTION, _myCode, SIZE_OF_INSTRUCTION);
				return true;
			}

			return false;
		}
	};
}