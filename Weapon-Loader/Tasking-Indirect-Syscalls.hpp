#pragma once
#include <iostream>
#include <Windows.h>
#include <map>
#include <cstdint>
#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <winternl.h>
#include <vector>
#include "Hashing.hpp"
#include "Structures.hpp"
#include "FunctionPointers.hpp"


#define STATUS_HASHES_NOT_RESOLVED (NTSTATUS)0x42069
#define STATUS_HASH_DOES_NOT_EXIST (NTSTATUS)0x6969
#define STATUS_IDS_FUNCTION_NOT_FOUND (NTSTATUS)0xbabecafe
#define STATUS_FUNCTION_PTR_NOT_FOUND (NTSTATUS)0xdeadbeef


extern "C" void SetSyscallValues(WORD SSN, void* JumpAddress);
extern "C" NTSTATUS SyscallGeneric(...);