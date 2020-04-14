#include "stdafx.h"

void PrintBytes(
    IN BYTE* pbPrintData,
    IN DWORD    cbDataLen)
{
    DWORD dwCount = 0;

    for (dwCount = 0; dwCount < cbDataLen; dwCount++) {
        printf("0x%02x ", pbPrintData[dwCount]);
    }

}

int wmain(int argc, wchar_t* argv[]) {
    BYTE _rgbIV[] = { '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00' };
    BYTE _rgbAESKey[] = { '\x41', '\x41', '\x41', '\x41', '\x41', '\x41', '\x41', '\x41', '\x41', '\x41', '\x41', '\x41', '\x41', '\x41', '\x41', '\x41' };
    BYTE _rgbPlaintext[] = { '\x48', '\x65', '\x6c', '\x6c', '\x6f', '\x2c', '\x20', '\x41', '\x45', '\x53', '\x21', '\x21', '\x21', '\x21', '\x21', '\x0a', '\x54', '\x68', '\x69', '\x73', '\x20', '\x69', '\x73', '\x20', '\x74', '\x65', '\x73', '\x74', '\x20', '\x70', '\x6c', '\x61', '\x69', '\x6e', '\x20', '\x74', '\x65', '\x78', '\x74', '\x21', '\x21' };

    Worker worker(_rgbIV, _rgbAESKey, _rgbPlaintext, sizeof(_rgbPlaintext));
    worker.Encrypt();
    PBYTE plainText = worker.getPlainText();
    PBYTE cipherText = worker.getCipherText();

    PrintBytes(plainText, sizeof(_rgbPlaintext));
    std::cout << std::endl;
    std::cout << std::endl;
    PrintBytes(cipherText, 48);
    /*  c9	3c	af	f4	5d	3e	ef	bb	dd	0c	cc	fe	83	f1	78	69
        32	a8	cb	a4	99	ed	fd	17	f8	fe	18	58	19	58	29	23
        5b	a1	83	1c	b7	13	92	ba	24 */
    return 0;
}