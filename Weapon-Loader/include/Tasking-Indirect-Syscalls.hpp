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
#include "Macro.hpp"


namespace IndirectSyscalls {

	bool Initialize();

	NTSTATUS NtAllocateVirtualMemory(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		ULONG_PTR ZeroBits,
		PSIZE_T   RegionSize,
		ULONG     AllocationType,
		ULONG     Protect);

	NTSTATUS NtProtectVirtualMemory(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		PSIZE_T RegionSize,
		ULONG NewProtect,
		PULONG OldProtect);

	NTSTATUS NtCreateUserProcess(
		PHANDLE ProcessHandle,
		PHANDLE ThreadHandle,
		ACCESS_MASK ProcessDesiredAccess,
		ACCESS_MASK ThreadDesiredAccess,
		POBJECT_ATTRIBUTES ProcessObjectAttributes,
		POBJECT_ATTRIBUTES ThreadObjectAttributes,
		ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
		ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
		PVOID ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
		PPS_CREATE_INFO CreateInfo,
		PPS_ATTRIBUTE_LIST AttributeList);

	NTSTATUS NtQueueApcThread(
		HANDLE ThreadHandle,
		void* ApcRoutine,
		PVOID ApcArgument1,
		PVOID ApcArgument2,
		PVOID ApcArgument3);

	NTSTATUS NtWriteVirtualMemory(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		PVOID Buffer,
		SIZE_T BufferSize,
		PSIZE_T NumberOfBytesWritten);

	NTSTATUS NtResumeThread(
		HANDLE ThreadHandle,
		PULONG PreviousSuspendCount //Optional.
	);

}
