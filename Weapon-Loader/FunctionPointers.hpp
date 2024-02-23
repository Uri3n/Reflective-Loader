#pragma once
#include <Windows.h>
#include <winternl.h>


typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(

	HANDLE    ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
);


typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
	
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID* BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtect,
	_Out_ PULONG OldProtect
);


typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(

	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_ PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
);


typedef NTSTATUS(NTAPI* fnNtQueueApcThread)(
	
	_In_ HANDLE ThreadHandle,
	_In_ void* ApcRoutine,
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
);


typedef BOOL(WINAPI* fnCreateProcessW)(

	LPCWSTR               lpApplicationName,
	LPWSTR                lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCWSTR               lpCurrentDirectory,
	LPSTARTUPINFOW        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
);

typedef LPVOID(WINAPI* fnVirtualAllocEx)(

	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

typedef BOOL(WINAPI* fnWriteProcessMemory)(

	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten
);

typedef HANDLE(WINAPI* fnCreateThread)(

	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	LPVOID					lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
);

typedef DWORD(WINAPI* fnQueueUserApc)(

	PAPCFUNC  pfnAPC,
	HANDLE    hThread,
	ULONG_PTR dwData
);

typedef UINT(WINAPI* fnGetWindowsDirectoryW)(

	LPWSTR lpBuffer,
	UINT   uSize
);


typedef HRSRC(WINAPI* fnFindResourceW)(

	HMODULE hModule,
	LPCWSTR lpName,
	LPCWSTR lpType
);

typedef HGLOBAL(WINAPI* fnLoadResource)(

	HMODULE hModule,
	HRSRC   hResInfo
);

typedef LPVOID(WINAPI* fnLockResource)(

	HGLOBAL hResData
);

typedef DWORD(WINAPI* fnSizeofResource)(

	HMODULE hModule,
	HRSRC   hResInfo
);


typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx)(

	PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
	PUNICODE_STRING					ImagePathName,
	PUNICODE_STRING					DllPath,
	PUNICODE_STRING					CurrentDirectory,
	PUNICODE_STRING					CommandLine,
	PVOID							Environment,
	PUNICODE_STRING					WindowTitle,
	PUNICODE_STRING					DesktopInfo,
	PUNICODE_STRING					ShellInfo,
	PUNICODE_STRING					RuntimeData,
	ULONG							Flags
);