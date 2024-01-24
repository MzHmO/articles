#pragma once
#include <Windows.h>
#include <iostream>
#include <string>

void BuildDecodingTable();
unsigned char* DecodeBase64(const char* data, size_t input_length, size_t* output_length);
LPCSTR EncodeBase64(BYTE* buffer, size_t in_len);