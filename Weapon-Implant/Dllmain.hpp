#pragma once
#include <Windows.h>
#include <winternl.h>
#include "Hashing.hpp"
#include "Structures.hpp"
#include "FunctionPointers.hpp"



typedef unsigned long long u64;
typedef unsigned long u32;
typedef unsigned short u16;

typedef signed long long i64;
typedef signed long i32;
typedef signed short i16;



extern void* __cdecl memset(void*, int, size_t);

#pragma intrinsic(memset)
#pragma function(memset)

void* __cdecl memset(void* Destination, int Value, size_t Size) {

	unsigned char* p = (unsigned char*)Destination;
	while (Size > 0) {
		*p = (unsigned char)Value;
		p++;
		Size--;
	}
	return Destination;
}




#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))



PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size)
{
	for (volatile int i = 0; i < Size; i++) {
		((BYTE*)Destination)[i] = ((BYTE*)Source)[i];
	}
	return Destination;
}



byte* GetModuleHandleH(u32 ModuleHash) {

	PPEB pPeb = (PPEB)__readgsqword(0x60);

	PLDR_DATA_TABLE_ENTRY pDataEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pPeb->Ldr->InMemoryOrderModuleList.Flink);
	PLIST_ENTRY pListHead = reinterpret_cast<PLIST_ENTRY>(&(pPeb->Ldr->InMemoryOrderModuleList));
	PLIST_ENTRY pItr = reinterpret_cast<PLIST_ENTRY>(pListHead->Flink);


	do {

		if (pDataEntry->FullDllName.Length) {

			if (JenkinsHash(NULL, pDataEntry->FullDllName.Buffer) == ModuleHash) {
				return static_cast<byte*>(pDataEntry->Reserved2[0]);
				break;
			}
		}

		pDataEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pItr->Flink);
		pItr = (PLIST_ENTRY)(pItr->Flink);


	} while (pItr != pListHead);

	return nullptr;
}



void* GetProcAddressH(HMODULE ModuleBase, u32 FunctionHash) {

	byte* Base = reinterpret_cast<byte*>(ModuleBase);

	PIMAGE_NT_HEADERS pImgNtHdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;


	PIMAGE_EXPORT_DIRECTORY pImgExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY> \
		(Base + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


	u32* Names = reinterpret_cast<u32*>(Base + pImgExportDirectory->AddressOfNames);
	u32* Addresses = reinterpret_cast<u32*>(Base + pImgExportDirectory->AddressOfFunctions);
	u16* Ordinals = reinterpret_cast<u16*>(Base + pImgExportDirectory->AddressOfNameOrdinals);


	for (size_t i = 0; i < pImgExportDirectory->NumberOfFunctions; i++) {

		char* Name = (char*)(Base + Names[i]);
		void* Address = (void*)(Base + Addresses[Ordinals[i]]);

		if (JenkinsHash(Name, NULL) == FunctionHash)
			return Address;
	}

	return nullptr;
}



CREATEHASHA(GetProcAddress);
CREATEHASHA(LoadLibraryA);
CREATEHASHA(VirtualAlloc);
CREATEHASHA(VirtualProtect);
CREATEHASHA(NtFlushInstructionCache);

CREATEHASHW(KERNEL32);
CREATEHASHW(ntdll);