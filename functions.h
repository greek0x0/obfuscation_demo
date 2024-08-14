#ifndef FUNCTIONS_H
#define FUNCTIONS_H

/* --- TODO LIST --- */
// ADD function to add payload to .TEXT section using custom NT API VirtualProtect, VirtualFree
// Implement XOR Encryption 
// Implement Securing the Encryption Key of XOR
// Implement Both methods of RC4 encryption
// Implement AES Encryption 
// Implement MacFuscaion with IPv4/IPV6 addresses 
// Implement UUID deobfuscation+ Obfuscation 
// Local Payload Execution - Shellcode function using NTAPI 
// Implement Shellcode Injection 
// 
/* -------- INCLUDES --------*/
#include <Windows.h>
#include <cstdarg> 
#include <stdio.h>
#include <iostream>
#include <cstring>
#include <cstdio>
//#include <winsock2.h>
//#include <ws2tcpip.h>
#include <io.h>
#include <fcntl.h>
#include <string>
#include <locale>
#include <codecvt>
using namespace std;


/* [-------- Global Variables -------] */
extern char big_string[];
extern char big_numbers[];
/* [-------- FUNCTION MACROS --------] */

/* Macros for rockyPrintColor */
#define rockyColor(baseColor) (FOREGROUND_##baseColor)
#define rockyColorBase(baseColor) (FOREGROUND_##baseColor | FOREGROUND_INTENSITY)
#define _WINSOCK_DEPRECATED_NO_WARNINGS

/* [CUSTOM GetModuleHandle https://learn.microsoft.com/en-us/windows/win32/api/ntdef/nf-ntdef-containing_record] */
#define CONTAINING_RECORD(address, type, field) \
    ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))


/* Macros for use with the NTAPI */
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/* [-------- CUSTOM FUNCTIONS --------] */


/* [CUSTOM: rockyGetModuleHandle (GetModuleHandle)]*/
HMODULE rockyGetModuleHandle(IN LPCWSTR szModuleName);
HMODULE rockyGetModuleHandle2(IN LPCWSTR szModuleName);

/* [CUSTOM: rockyGetProcAddress (GetProcAddress)] */
void* rockyGetProcAddress(HMODULE hModule, const char* functionName);

/* [CUSTOM: rockyPrintColor (printf())]*/
enum ConsoleColor {
	red = rockyColorBase(RED),
	green = rockyColorBase(GREEN),
	blue = rockyColorBase(BLUE),
	yellow = rockyColor(RED) | rockyColorBase(GREEN),
	purple = rockyColor(RED) | rockyColorBase(BLUE),
	white = rockyColor(RED) | rockyColor(GREEN) | rockyColorBase(BLUE),
	grey = rockyColor(RED) | rockyColor(GREEN) | rockyColor(BLUE),
	default_color = 15
};
void rockyPrintColor(ConsoleColor color, const char* format, ...);

/* [CUSTOM: rockyAlloc (Alloc)] */
void* rockyAlloc(const void* data, size_t size);
void* rockyAlloc(const char* stringData);


/* [CUSTOM: rockyLoadLibrary (LoadLibrary)] */
void* rockyLoadLibrary(const wchar_t* dllName);

/* [CUSTOM: rockyDealloc (Dealloc)] */
void rockyDealloc(void* pAddress);


/* [CUSTOM: rockyPrintAllocated (Show Payload)]*/
void rockyPrintAllocated(const void* pAddress, size_t size);

/* [CUSTOM rockyObfuscation and GetString (Obfuscator)] */
string rockyGetString(int offsets[], char* big_string, int sizeof_offset);
void rockyObfuscation(char* big_string, char* original_string);

/* [CUSTOM convert strings to Wstring] */
wstring stringToWstring(const string& str);

#endif // FUNCTIONS_H
