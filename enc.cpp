#include "stdafx.h"

Worker::Worker(PBYTE _rgbIV /* size: 16bytes */, PBYTE _rgbAESKey /* size: Key Size (bytes: 16 or ...etc) */, PBYTE _rgbPlaintext, ULONG _rgbPlaintextLength) {
	this->hAesAlg = NULL;
	this->hKey = NULL;
	this->status = NULL;
	this->cbCipherText = 0;
	this->cbPlainText = 0;
	this->cbData = 0;
	this->cbKeyObject = 0;
	this->cbBlockLen = 0;
	this->cbBlob = 0;
	this->pbCipherText = NULL;
	this->pbPlainText = NULL;
	this->pbKeyObject = NULL;
	this->pbIV = NULL;
	this->pbBlob = NULL;

	this->rgbIV = _rgbIV;
	this->rgbAESKey = _rgbAESKey;
	this->rgbPlaintext = _rgbPlaintext;
	this->rgbPlaintextLength = _rgbPlaintextLength;
}

Worker::~Worker() {
	if (hAesAlg)        BCryptCloseAlgorithmProvider(hAesAlg, 0);
	if (hKey)           BCryptDestroyKey(hKey);
	if (pbCipherText)   HeapFree(GetProcessHeap(), 0, pbCipherText);
	if (pbPlainText)    HeapFree(GetProcessHeap(), 0, pbPlainText);
	if (pbKeyObject)    HeapFree(GetProcessHeap(), 0, pbKeyObject);
	if (pbIV)           HeapFree(GetProcessHeap(), 0, pbIV);
}

BOOL Worker::Encrypt() {
	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) {
		wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
		goto Cleanup;
	}

	if (!NT_SUCCESS(status = BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0))) {
		wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
		goto Cleanup;
	}

	pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
	if (NULL == pbKeyObject) {
		wprintf(L"**** memory allocation failed\n");
		goto Cleanup;
	}

	if (!NT_SUCCESS(status = BCryptGetProperty(hAesAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&cbBlockLen, sizeof(DWORD), &cbData, 0))) {
		wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
		goto Cleanup;
	}

	if (cbBlockLen > AES_CBC_IV_SIZE) {
		wprintf(L"**** block length is longer than the provided IV length\n");
		goto Cleanup;
	}

	pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlockLen);
	if (NULL == pbIV) {
		wprintf(L"**** memory allocation failed\n");
		goto Cleanup;
	}
	memcpy(pbIV, rgbIV, cbBlockLen);

	if (!NT_SUCCESS(status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0))) {
		wprintf(L"**** Error 0x%x returned by BCryptSetProperty\n", status);
		goto Cleanup;
	}

	if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(hAesAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)rgbAESKey, AES_CBC_KEY_SIZE, 0))) {
		wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
		goto Cleanup;
	}

	if (!NT_SUCCESS(status = BCryptExportKey(hKey, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, 0, &cbBlob, 0))) {
		wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
		goto Cleanup;
	}

	pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob);
	if (NULL == pbBlob) {
		wprintf(L"**** memory allocation failed\n");
		goto Cleanup;
	}

	if (!NT_SUCCESS(status = BCryptExportKey(hKey, NULL, BCRYPT_OPAQUE_KEY_BLOB, pbBlob, cbBlob, &cbBlob, 0))) {
		wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
		goto Cleanup;
	}

	cbPlainText = rgbPlaintextLength;
	pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
	if (NULL == pbPlainText)
	{
		wprintf(L"**** memory allocation failed\n");
		goto Cleanup;
	}

	memcpy(pbPlainText, rgbPlaintext, rgbPlaintextLength);

	if (!NT_SUCCESS(status = BCryptEncrypt(hKey, pbPlainText, cbPlainText, NULL, pbIV, cbBlockLen, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING))) {
		wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
		goto Cleanup;
	}

	pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
	if (NULL == pbCipherText) {
		wprintf(L"**** memory allocation failed\n");
		goto Cleanup;
	}

	// Use the key to encrypt the plaintext buffer.
	// For block sized messages, block padding will add an extra block.
	if (!NT_SUCCESS(status = BCryptEncrypt(hKey, pbPlainText, cbPlainText, NULL, pbIV, cbBlockLen, pbCipherText, cbCipherText, &cbData, BCRYPT_BLOCK_PADDING))) {
		wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
		goto Cleanup;
	}

	// Destroy the key and reimport from saved BLOB.
	if (!NT_SUCCESS(status = BCryptDestroyKey(hKey))) {
		wprintf(L"**** Error 0x%x returned by BCryptDestroyKey\n", status);
		goto Cleanup;
	}
	hKey = 0;

	if (pbPlainText) {
		HeapFree(GetProcessHeap(), 0, pbPlainText);
	}

	pbPlainText = NULL;

	// We can reuse the key object.
	memset(pbKeyObject, 0, cbKeyObject);

	// Reinitialize the IV because encryption would have modified it.
	memcpy(pbIV, rgbIV, cbBlockLen);

	if (!NT_SUCCESS(status = BCryptImportKey(hAesAlg, NULL, BCRYPT_OPAQUE_KEY_BLOB, &hKey, pbKeyObject, cbKeyObject, pbBlob, cbBlob, 0))) {
		wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
		goto Cleanup;
	}

	//
	// Get the output buffer size.
	//
	if (!NT_SUCCESS(status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, pbIV, cbBlockLen, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING))) {
		wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", status);
		goto Cleanup;
	}

	pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
	if (NULL == pbPlainText) {
		wprintf(L"**** memory allocation failed\n");
		goto Cleanup;
	}

	if (!NT_SUCCESS(status = BCryptDecrypt(hKey, pbCipherText, cbCipherText, NULL, pbIV, cbBlockLen, pbPlainText, cbPlainText, &cbPlainText, BCRYPT_BLOCK_PADDING))) {
		wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", status);
		goto Cleanup;
	}

	if (0 != memcmp(pbPlainText, (PBYTE)rgbPlaintext, 16 /* sizeof(rgbPlaintext) */)) {
		wprintf(L"Expected decrypted text comparison failed.\n");
		goto Cleanup;
	}

	wprintf(L"Success!\n");
	return true;

Cleanup:
	if (hAesAlg)        BCryptCloseAlgorithmProvider(hAesAlg, 0);
	if (hKey)           BCryptDestroyKey(hKey);
	if (pbCipherText)   HeapFree(GetProcessHeap(), 0, pbCipherText);
	if (pbPlainText)    HeapFree(GetProcessHeap(), 0, pbPlainText);
	if (pbKeyObject)    HeapFree(GetProcessHeap(), 0, pbKeyObject);
	if (pbIV)           HeapFree(GetProcessHeap(), 0, pbIV);
	return false;
}

PBYTE Worker::getPlainText() {
	return this->pbPlainText;
}

PBYTE Worker::getCipherText() {
	return this->pbCipherText;
}