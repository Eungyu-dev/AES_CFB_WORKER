#pragma once

#include <Windows.h>
#include <bcrypt.h>
#include <atlstr.h>

#include <iostream>
#include <string>
#include <fstream>
#include <vector>

#include <sstream>
#include <cstdio>
#include <cstring>

#include "enc.h"

#pragma comment(lib, "bcrypt.lib")
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#define _CRT_SECURE_NO_WARNINGS
#define AES_CBC_IV_SIZE 16
#define AES_CBC_KEY_SIZE 16