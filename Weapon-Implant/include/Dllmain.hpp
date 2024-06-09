#pragma once
#include <Windows.h>
#include <winternl.h>
#include "Hashing.hpp"
#include "Structures.hpp"
#include "FunctionPointers.hpp"
#include "Macro.hpp"


//
// random garbage I don't know where to place
//

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

PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size)
{
	for (volatile int i = 0; i < Size; i++) {
		((BYTE*)Destination)[i] = ((BYTE*)Source)[i];
	}
	return Destination;
}







