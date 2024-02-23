#pragma once
#include <Windows.h>


constexpr size_t StringLengthCustomA(const char* string) {

	size_t counter = 0;
	while (*string != '\0') {

		++counter;
		++string;
	}

	return counter;
}


constexpr size_t StringLengthCustomW(const wchar_t* string) {

	size_t counter = 0;
	while (*string != L'\0') {

		++counter;
		++string;
	}

	return counter;
}




constexpr int randomSeed() {

	return 0x3A * 420 +

		__TIME__[0] +
		__TIME__[1] +
		__TIME__[2] +
		__TIME__[3] +
		__TIME__[4] +
		__TIME__[5] +
		__TIME__[6] +
		__TIME__[7];
}

constexpr int hashSeed = randomSeed();






constexpr ULONG JenkinsHash(const char* asciiString, const wchar_t* wideString) {



	ULONG HASH = (ULONG)hashSeed;

	if ((!asciiString && !wideString) || (asciiString && wideString)) {
		return NULL;
	}

	size_t strLen = (asciiString ? StringLengthCustomA(asciiString) : StringLengthCustomW(wideString));


	for (size_t i = 0; i < strLen; i++) {

		if (asciiString) {
			if (asciiString[i] == '.') {
				break;
			}
		}

		else {
			if (wideString[i] == L'.') {
				break;
			}
		}


		asciiString ? HASH += asciiString[i] : HASH += wideString[i];
		HASH += (HASH << 10);
		HASH ^= (HASH >> 6);
	}


	HASH += (HASH << 3);
	HASH ^= (HASH >> 11);
	HASH += (HASH << 15);

	return HASH;
}


#define CREATEHASHW(name) constexpr auto name##_compHashedW = JenkinsHash(NULL, (const wchar_t* )L#name);
#define CREATEHASHA(name) constexpr auto name##_compHashedA = JenkinsHash((const char*)#name, NULL);
