#pragma once
#include <Windows.h>


struct PE_INFO {

	byte* pMappedData = nullptr;
	size_t ImageSize = 0;

	PIMAGE_NT_HEADERS        pImgNtHdrs = nullptr;
	PIMAGE_SECTION_HEADER    pImgSecHdr = nullptr;

	PIMAGE_DATA_DIRECTORY    pEntryImportDataDir = nullptr;
	PIMAGE_DATA_DIRECTORY    pEntryBaseRelocDataDir = nullptr;
	PIMAGE_DATA_DIRECTORY    pEntryTLSDataDir = nullptr;
	PIMAGE_DATA_DIRECTORY    pEntryExceptionDataDir = nullptr;
	PIMAGE_DATA_DIRECTORY    pEntryExportDataDir = nullptr;

	bool InitComplete = false;
};


typedef struct _BASE_RELOCATION_ENTRY {
	WORD	Offset : 12;
	WORD	Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;