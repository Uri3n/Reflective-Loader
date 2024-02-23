#pragma once
#include <iostream>
#include <cstdint>
#include <Windows.h>
#include <winternl.h>
#include <array>
#include "Hashing.hpp"
#include "resource.h"
#include "Structures.hpp"
#include "Utilities.hpp"
#include "FunctionPointers.hpp"


#define DLL_MITIGATION_POLICY PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001
#define PROCESS_CREATE_FLAGS_SUSPENDED 0x00000200		//Only for NtCreateUserProcess
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001


#define INDEX_IMAGENAME 0 
#define INDEX_COMMANDLINE 1 
#define INDEX_CURRENT_DIRECTORY 2


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