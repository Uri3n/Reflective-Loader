#pragma once
#include <Windows.h>


typedef enum _PS_CREATE_STATE
{
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName,
	PsCreateSuccess,
	PsCreateMaximumStates

} PS_CREATE_STATE;


typedef struct _PS_CREATE_INFO
{
	SIZE_T Size;
	PS_CREATE_STATE State;
	union
	{
		struct
		{
			union
			{
				ULONG InitFlags;
				struct
				{
					UCHAR WriteOutputOnExit : 1;
					UCHAR DetectManifest : 1;
					UCHAR IFEOSkipDebugger : 1;
					UCHAR IFEODoNotPropagateKeyState : 1;
					UCHAR SpareBits1 : 4;
					UCHAR SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				} s1;
			} u1;
			ACCESS_MASK AdditionalFileAccess;
		} InitState;

		struct
		{
			HANDLE FileHandle;
		} FailSection;

		struct
		{
			USHORT DllCharacteristics;
		} ExeFormat;

		struct
		{
			HANDLE IFEOKey;
		} ExeName;

		struct
		{
			union
			{
				ULONG OutputFlags;
				struct
				{
					UCHAR ProtectedProcess : 1;
					UCHAR AddressSpaceOverride : 1;
					UCHAR DevOverrideEnabled : 1;
					UCHAR ManifestDetected : 1;
					UCHAR ProtectedProcessLight : 1;
					UCHAR SpareBits1 : 3;
					UCHAR SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				} s2;
			} u2;
			HANDLE FileHandle;
			HANDLE SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG UserProcessParametersWow64;
			ULONG CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG ManifestSize;
		} SuccessState;
	};

} PS_CREATE_INFO, * PPS_CREATE_INFO;




typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;
	SIZE_T Size;
	union
	{
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;

} PS_ATTRIBUTE, * PPS_ATTRIBUTE;



typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[2]; //Block DLL policy and imagename

} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;



#define PS_ATTRIBUTE_NUMBER_MASK    0x0000ffff
#define PS_ATTRIBUTE_THREAD         0x00010000 // Attribute may be used with thread creation
#define PS_ATTRIBUTE_INPUT          0x00020000 // Attribute is input only
#define PS_ATTRIBUTE_ADDITIVE       0x00040000 // Attribute may be "accumulated", e.g. bitmasks, counters, etc.

//\
https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L1930

typedef enum _PS_ATTRIBUTE_NUM
{
	PsAttributeParentProcess,                   // in HANDLE
	PsAttributeDebugPort,                       // in HANDLE
	PsAttributeToken,                           // in HANDLE
	PsAttributeClientId,                        // out PCLIENT_ID
	PsAttributeTebAddress,                      // out PTEB
	PsAttributeImageName,                       // in PWSTR
	PsAttributeImageInfo,                       // out PSECTION_IMAGE_INFORMATION
	PsAttributeMemoryReserve,                   // in PPS_MEMORY_RESERVE
	PsAttributePriorityClass,                   // in UCHAR
	PsAttributeErrorMode,                       // in ULONG
	PsAttributeStdHandleInfo,                   // in PPS_STD_HANDLE_INFO
	PsAttributeHandleList,                      // in PHANDLE
	PsAttributeGroupAffinity,                   // in PGROUP_AFFINITY
	PsAttributePreferredNode,                   // in PUSHORT
	PsAttributeIdealProcessor,                  // in PPROCESSOR_NUMBER
	PsAttributeUmsThread,                       // see MSDN UpdateProceThreadAttributeList (CreateProcessW) - in PUMS_CREATE_THREAD_ATTRIBUTES
	PsAttributeMitigationOptions,               // in UCHAR
	PsAttributeProtectionLevel,                 // in ULONG
	PsAttributeSecureProcess,                   // since THRESHOLD (Virtual Secure Mode, Device Guard)
	PsAttributeJobList,
	PsAttributeChildProcessPolicy,              // since THRESHOLD2
	PsAttributeAllApplicationPackagesPolicy,    // since REDSTONE
	PsAttributeWin32kFilter,
	PsAttributeSafeOpenPromptOriginClaim,
	PsAttributeBnoIsolation,
	PsAttributeDesktopAppPolicy,
	PsAttributeMax
} PS_ATTRIBUTE_NUM;



//\
https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L1974

#define PsAttributeValue(Number, Thread, Input, Additive)		\
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK)	|					\
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0)	|					\
    ((Input) ? PS_ATTRIBUTE_INPUT : 0)		|					\
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

// Specifies the parent process of the new process
#define PS_ATTRIBUTE_PARENT_PROCESS \
    PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE)
// Specifies the debug port to use
#define PS_ATTRIBUTE_DEBUG_PORT \
    PsAttributeValue(PsAttributeDebugPort, FALSE, TRUE, TRUE)
// Specifies the token to assign to the new process
#define PS_ATTRIBUTE_TOKEN \
    PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE)
// Specifies the client ID to assign to the new process
#define PS_ATTRIBUTE_CLIENT_ID \
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)
// Specifies the TEB address to use for the new process
#define PS_ATTRIBUTE_TEB_ADDRESS \
    PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE)
// Specifies the image name of the new process
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
// Specifies the image information of the new process
#define PS_ATTRIBUTE_IMAGE_INFO \
    PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE)
// Specifies the amount of memory to reserve for the new process
#define PS_ATTRIBUTE_MEMORY_RESERVE \
    PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE)
// Specifies the priority class to use for the new process
#define PS_ATTRIBUTE_PRIORITY_CLASS \
    PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE)
// Specifies the error mode to use for the new process
#define PS_ATTRIBUTE_ERROR_MODE \
    PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE)
// Specifies the standard handle information to use for the new process
#define PS_ATTRIBUTE_STD_HANDLE_INFO \
    PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE)
// Specifies the handle list to use for the new process
#define PS_ATTRIBUTE_HANDLE_LIST \
    PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE)
// Specifies the group affinity to use for the new process
#define PS_ATTRIBUTE_GROUP_AFFINITY \
    PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE)
// Specifies the preferred NUMA node to use for the new process
#define PS_ATTRIBUTE_PREFERRED_NODE \
    PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE)
// Specifies the ideal processor to use for the new process
#define PS_ATTRIBUTE_IDEAL_PROCESSOR \
    PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE)
// Specifies the process mitigation options to use for the new process
#define PS_ATTRIBUTE_MITIGATION_OPTIONS \
    PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, FALSE)
// Specifies the protection level to use for the new process
#define PS_ATTRIBUTE_PROTECTION_LEVEL \
    PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, FALSE)
// Specifies the UMS thread to associate with the new process
#define PS_ATTRIBUTE_UMS_THREAD \
    PsAttributeValue(PsAttributeUmsThread, TRUE, TRUE, FALSE)
// Specifies whether the new process is a secure process
#define PS_ATTRIBUTE_SECURE_PROCESS \
    PsAttributeValue(PsAttributeSecureProcess, FALSE, TRUE, FALSE)
// Specifies the job list to associate with the new process
#define PS_ATTRIBUTE_JOB_LIST \
    PsAttributeValue(PsAttributeJobList, FALSE, TRUE, FALSE)
// Specifies the child process policy to use for the new process
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY \
    PsAttributeValue(PsAttributeChildProcessPolicy, FALSE, TRUE, FALSE)
// Specifies the all application packages policy to use for the new process
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY \
    PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, FALSE, TRUE, FALSE)
// Specifies the child process should have access to the Win32k subsystem.
#define PS_ATTRIBUTE_WIN32K_FILTER	\
    PsAttributeValue(PsAttributeWin32kFilter, FALSE, TRUE, FALSE)
// Specifies the child process is allowed to claim a specific origin when making a safe file open prompt
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM	\
    PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
// Specifies the child process is isolated using the BNO framework
#define PS_ATTRIBUTE_BNO_ISOLATION	\
    PsAttributeValue(PsAttributeBnoIsolation, FALSE, TRUE, FALSE)
// Specifies that the child's process desktop application policy  
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY	\
    PsAttributeValue(PsAttributeDesktopAppPolicy, FALSE, TRUE, FALSE)