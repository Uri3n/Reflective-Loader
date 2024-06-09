#pragma once
#include <Windows.h>
#include <winternl.h>
#include <cstdint>
#include <iostream>
#include "Hashing.hpp"
#include "Macro.hpp"


void* GetProcAddressH(HMODULE ModuleBase, std::uint32_t FunctionHash);
byte* GetModuleHandleH(std::uint32_t ModuleHash);
void _RtlInitUnicodeString(_Out_ PUNICODE_STRING UsStruct, _In_opt_ PCWSTR Buffer);
std::uint32_t getFileOffsetFromRva(std::uint32_t RVA, _In_ byte* fileBase);
std::uint32_t getReflectiveFunctionRawOffset(byte* fileBase, const char* reflectiveFunctionName);
void Decrypt(byte* PayloadBuffer, size_t payloadSize);
