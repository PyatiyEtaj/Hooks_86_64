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
		/*
		* mov r15, absolute_adress_to_function
		* jmp r15
		*/
		const uintptr_t SIZE_OF_INSTRUCTION = Hooks_Hooks64_SAFE_BYTES_MIN;

		PBYTE _originalCode = nullptr;
		PBYTE _myCode = nullptr;
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
		void CheckCountOfSafeBytes(uint64_t countOfSafeBytes)
		{
			if (countOfSafeBytes > Hooks_Hooks64_SAFE_BYTES_MAX || countOfSafeBytes < Hooks_Hooks64_SAFE_BYTES_MIN)
				throw std::exception("Count of safe bytes issue");
		}

		void Init(PBYTE functionToHook, PBYTE newFunction, uint32_t countOfSafeByte)
		{
			_originalCode = (PBYTE)calloc(countOfSafeByte, sizeof(BYTE));
			_myCode = (PBYTE)calloc(countOfSafeByte, sizeof(BYTE));
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
				changedCode[safe] = 0x49;
				changedCode[safe+1] = 0xBF;
				changedCode[safe+10] = 0x41;
				changedCode[safe+11] = 0xFF;
				changedCode[safe+12] = 0xE7;
				uintptr_t addr = (uintptr_t)(adr + safe);
				memcpy_s(changedCode + (safe + 2), sizeof(uintptr_t), (void*)&addr, sizeof(uintptr_t));
				DWORD temp;
				VirtualProtect(changedCode, Hooks_Hooks64_BYTES_BACKUP, PAGE_EXECUTE_READWRITE, &temp);
			}
			return changedCode;
		}

		bool SetHook(PBYTE newFunction, PBYTE functionToHook)
		{
			DWORD oldProtectDip = 0;
			if (VirtualProtect((PBYTE)functionToHook, 16, PAGE_EXECUTE_READWRITE, &oldProtectDip))
			{
				memcpy_s(_originalCode, _countOfSafeByte, functionToHook, _countOfSafeByte);
				_myCode[0] = 0x49;
				_myCode[1] = 0xBF;
				_myCode[10] = 0x41;
				_myCode[11] = 0xFF;
				_myCode[12] = 0xE7;
				uintptr_t addr = (uintptr_t)newFunction;
				memcpy_s(_myCode + 2, sizeof(uintptr_t), (void*)&addr, sizeof(uintptr_t));
				memcpy_s(functionToHook, SIZE_OF_INSTRUCTION, _myCode, SIZE_OF_INSTRUCTION);
				return true;
			}

			return false;
		}
	};
}