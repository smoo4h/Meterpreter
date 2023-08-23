#include <iostream>
#include <string>
#include <windows.h>
#include <wincrypt.h>
//#include "../../Testing/run-tests/base64.h"

//#include <gtest/gtest.h>

#pragma comment(lib, "Crypt32.lib")

BOOL Base64EncodeA(const unsigned char* src, const unsigned long slen, char** dst, unsigned long* dlen)
{
	DWORD encodedLength = 0;
	if (!CryptBinaryToStringA(src, slen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &encodedLength))
	{
		return FALSE;
	}

	*dst = new char[encodedLength];
	if (!CryptBinaryToStringA(src, slen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *dst, &encodedLength))
	{
		delete[] * dst;
		return FALSE;
	}

	*dlen = encodedLength;
	return TRUE;
}

BOOL Base64DecodeA(const unsigned char* src, const unsigned long slen, char** dst, unsigned long* dlen)
{
	DWORD decodedLength = 0;
	if (!CryptStringToBinaryA(reinterpret_cast<LPCSTR>(src), slen, CRYPT_STRING_BASE64, nullptr, &decodedLength, nullptr, nullptr))
	{
		return FALSE;
	}

	*dst = new char[decodedLength];
	if (!CryptStringToBinaryA(reinterpret_cast<LPCSTR>(src), slen, CRYPT_STRING_BASE64, reinterpret_cast<BYTE*>(*dst), &decodedLength, nullptr, nullptr))
	{
		delete[] * dst;
		return FALSE;
	}

	*dlen = decodedLength;
	return TRUE;
}

BOOL Base64Encode(const std::string& in, std::string* out)
{
	char* dst = nullptr;
	unsigned long dlen = 0;
	bool ret = Base64EncodeA(reinterpret_cast<const unsigned char*>(in.c_str()), static_cast<unsigned long>(in.length()), &dst, &dlen);
	if (ret)
	{
		*out = std::string(dst, dlen);
		SecureZeroMemory(dst, dlen);
		delete[] dst;
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL Base64Decode(const std::string& in, std::string* out)
{
	char* dst = nullptr;
	unsigned long dlen = 0;
	bool ret = Base64DecodeA(reinterpret_cast<const unsigned char*>(in.c_str()), static_cast<unsigned long>(in.length()), &dst, &dlen);
	if (ret)
	{
		*out = std::string(dst, dlen);
		SecureZeroMemory(dst, dlen);
		delete[] dst;
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}