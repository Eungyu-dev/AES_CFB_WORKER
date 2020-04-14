#pragma once
#include "stdafx.h"

class Worker {
private:
	BCRYPT_ALG_HANDLE hAesAlg;
	BCRYPT_KEY_HANDLE hKey;
	NTSTATUS status;
	DWORD cbCipherText, cbPlainText, cbData, cbKeyObject, cbBlockLen, cbBlob;
	PBYTE pbCipherText, pbPlainText, pbKeyObject, pbIV, pbBlob;
	PBYTE rgbIV, rgbAESKey, rgbPlaintext;   //Additional custom data
	ULONG rgbPlaintextLength;

public:
	Worker(PBYTE _rgbIV /* size: 16bytes */, PBYTE _rgbAESKey /* size: Key Size (bytes: 16 or ...etc) */, PBYTE _rgbPlaintext, ULONG _rgbPlaintextLength);
	~Worker();
	BOOL Encrypt();
	PBYTE getPlainText();
	PBYTE getCipherText();
};