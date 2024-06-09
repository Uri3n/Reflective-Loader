#pragma once

typedef unsigned long long u64;
typedef unsigned long u32;
typedef unsigned short u16;

typedef signed long long i64;
typedef signed long i32;
typedef signed short i16;

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))