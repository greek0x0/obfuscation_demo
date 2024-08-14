#include "structures.h"
#include "functions.h"

char big_string[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._123456789";
char big_numbers[] = "1234567.890";


/* Obfuscated Strings | Currently Not used .  */
int str_LdrGetProcedureAddress[] = { 37,3,17,32,4,19,41,17,14,2,4,3,20,17,4,26,3,3,17,4,18,18 };
int str_ntdll_offsets[] = { 39, 45, 29, 37, 37, 52, 29, 37, 37 };
int str_LdrLoadDll[] = { 37,3,17,37,14,0,3,29,11,11 };
int str_NtAllocateVirtualMemory[] = { 39,19,26,11,11,14,2,0,19,4,47,8,17,19,20,0,11,38,4,12,14,17,24 };
int str_NtFreeVirtualMemory[] = { 39,19,31,17,4,4,47,8,17,19,20,0,11,38,4,12,14,17,24 };

void rockyObfuscation(char* big_string, char* original_string) {
	for (int i = 0; i < strlen(original_string); i++) {
		for (int j = 0; j < strlen(big_string); ++j) {
			if (original_string[i] == big_string[j]) {
				printf("%d,", j);
			}
		}
	}
}

/* [CUSTOM rockyGetString to get original string from the obfuscation] */
string rockyGetString(int offsets[], char* big_string, int sizeof_offset) {
	string empty_string = "";
	for (int i = 0; i < sizeof_offset / 4; ++i) {
		char character = big_string[offsets[i]];
		empty_string += character;
	}
	return empty_string;
}

/* [CUSTOM stringtoWstring converter] */
wstring stringToWstring(const string& str) {
	// This is a modern alternative for conversion
	wstring_convert<codecvt_utf8<wchar_t>> converter;
	return converter.from_bytes(str);
}
/* [CUSTOM rockyGetProcAddress function */
void* rockyGetProcAddress(HMODULE hModule, const char* functionName) {
	HMODULE NTDLL = rockyGetModuleHandle2(L"NTDLL.DLL");
	if (!NTDLL) {
		rockyPrintColor(red, "Failed to load NTDLL");
		return NULL;

	}

	s_LdrGetProcedureAddress LdrGetProcedureAddress = (s_LdrGetProcedureAddress)GetProcAddress(NTDLL, "LdrGetProcedureAddress");

	if (!LdrGetProcedureAddress) {
		rockyPrintColor(red, "Failed to get LdrGetProcedureAddress");
		return NULL;
	}
	ANSI_STRING ansiFunctionName;
	RtlInitAnsiString(&ansiFunctionName, functionName);
	PVOID functionAddress = NULL;

	NTSTATUS status = LdrGetProcedureAddress(hModule, &ansiFunctionName, 0, &functionAddress);

	if (status != 0) {
		rockyPrintColor(red, "Failed to retrive the address for %s", functionName);
		return NULL;
	}
	return functionAddress;
}

/* [CUSTOM GetModuleHandle Function helper that takes 2 strings, convert them to lowercase, compare them, and return true if both are equal, false otherwise] */
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {

	WCHAR lStr1[MAX_PATH], lStr2[MAX_PATH];

	int	len1 = lstrlenW(Str1), len2 = lstrlenW(Str2);

	int		i = 0,
		j = 0;

	// checking - we dont want to overflow our buffers
	if (len1 >= MAX_PATH || len2 >= MAX_PATH)
		return FALSE;

	// converting Str1 to lower case string (lStr1)
	for (i = 0; i < len1; i++) {
		lStr1[i] = (WCHAR)tolower(Str1[i]);
	}
	lStr1[i++] = L'\0'; // null terminating


	// converting Str2 to lower case string (lStr2)
	for (j = 0; j < len2; j++) {
		lStr2[j] = (WCHAR)tolower(Str2[j]);
	}
	lStr2[j++] = L'\0'; // null terminating


	// comparing the lower-case strings
	if (lstrcmpiW(lStr1, lStr2) == 0)
		return TRUE;

	return FALSE;
}

/* [CUSTOM GetModuleHandle Implementation Function that replaces GetModuleHandle, uses pointers to enumerate in the DLLs] */
HMODULE rockyGetModuleHandle(IN LPCWSTR szModuleName) {

	// getting peb
#ifdef _WIN64 // if compiling as x64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	// geting Ldr
	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	// getting the first element in the linked list (contains information about the first module)
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		// if not null
		if (pDte->FullDllName.Length != NULL) {

			// check if both equal
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);
#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif // STRUCTS

			}

			// wprintf(L"[i] \"%s\" \n", pDte->FullDllName.Buffer);
		}
		else {
			break;
		}

		// next element in the linked list
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

	}

	return NULL;
}

/* [CUSTOM GetModuleHandle Implementation Function that replaces GetModuleHandle, uses head and node to enumerate in DLL's uding doubly linked list concept] */
HMODULE rockyGetModuleHandle2(IN LPCWSTR szModuleName) {

#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pPeb->Ldr->InMemoryOrderModuleList.Flink);

	// getting the head of the linked list ( used to get the node & to check the end of the list)
	PLIST_ENTRY				pListHead = (PLIST_ENTRY)&pPeb->Ldr->InMemoryOrderModuleList;
	// getting the node of the linked list
	PLIST_ENTRY				pListNode = (PLIST_ENTRY)pListHead->Flink;

	do
	{
		if (pDte->FullDllName.Length != NULL) {
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);
#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif // STRUCTS
			}

			//wprintf(L"[i] \"%s\" \n", pDte->FullDllName.Buffer);

			// updating pDte to point to the next PLDR_DATA_TABLE_ENTRY in the linked list
			pDte = (PLDR_DATA_TABLE_ENTRY)(pListNode->Flink);

			// updating the node variable to be the next node in the linked list
			pListNode = (PLIST_ENTRY)pListNode->Flink;

		}

		// when the node is equal to the head, we reached the end of the linked list, so we break out of the loop
	} while (pListNode != pListHead);



	return NULL;
}

/* [CUSTOM LoadLibrary Implementation Function that replaces LoadLibrary] */
void* rockyLoadLibrary(const wchar_t* dllName) {
	UNICODE_STRING unicodeString;
	RtlInitUnicodeString(&unicodeString, dllName);

	HMODULE NTDLL = rockyGetModuleHandle2(L"NTDLL.DLL");
	if (!NTDLL) {
		rockyPrintColor(red, "Failed to load ntdll.dll");
		return NULL;
	}
	s_LdrLoadDll rockyLoadLibrary = (s_LdrLoadDll)rockyGetProcAddress(NTDLL, "LdrLoadDll");
	if (!rockyLoadLibrary) {
		rockyPrintColor(red, "Failed to retrieve LdrLoadDLl");
		return NULL;
	}

	HANDLE moduleHandle = NULL;
	NTSTATUS status = rockyLoadLibrary(NULL, 0, &unicodeString, &moduleHandle);
	if (status != 0) {
		rockyPrintColor(red, "Failed to load DLL: %ls", dllName);
		return NULL;
	}
	return moduleHandle;

}

/* [CUSTOM rockyPrintColor Implementation Function to print colors] */
void rockyPrintColor(ConsoleColor color, const char* format, ...) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	// Set the color
	SetConsoleTextAttribute(hConsole, color);
	// prepare its format
	char buffer[1024];
	va_list args;
	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	printf("%s\n", buffer);
	SetConsoleTextAttribute(hConsole, default_color);
}

/* [CUSTOM rockAlloc Implementation to Allocate data to memory] */
void* rockyAlloc(const void* data, size_t size) {

	/* Get the Module handle for ntdll.dll  : */
	HMODULE NTDLL = rockyGetModuleHandle2(L"NTDLL.DLL");
	if (NTDLL == NULL) {
		return NULL;
	}

	/* create our own AllocateVirtualMemory structutre*/
	s_NtAllocateVirtualMemory rockyAllocateVirtualMemory = (s_NtAllocateVirtualMemory)rockyGetProcAddress(NTDLL, "NtAllocateVirtualMemory");

	if (rockyAllocateVirtualMemory == NULL) {
		return NULL;
	}

	PVOID baseAddress = NULL;
	SIZE_T regionSize = size;


	NTSTATUS status = rockyAllocateVirtualMemory(GetCurrentProcess(), &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != 0) { return NULL; }
	memcpy(baseAddress, data, size);

}

/* [CUSTOM overloading rockyAlloc Implmentation to support string data] */
void* rockyAlloc(const char* stringData) {
	size_t size = strlen(stringData) + 1; // +1 for null terminator
	return rockyAlloc(static_cast<const void*>(stringData), size);
}

/* [CUSTOM rockyDealloc, used to free memory ] */
void rockyDealloc(void* pAddress) {
	if (pAddress == NULL) {
		printf("Invalid address to deallocate.\n");
		return;
	}

	HMODULE NTDLL_HANDLE = rockyGetModuleHandle2(L"NTDLL.DLL");
	if (NTDLL_HANDLE == NULL) {
		printf("Failed to load NTDLL.DLL.\n");
		return;
	}

	// Get the NtFreeVirtualMemory function from the NTDLL module
	s_NtFreeVirtualMemory rockyFreeVirtualMemory = (s_NtFreeVirtualMemory)rockyGetProcAddress(NTDLL_HANDLE, "NtFreeVirtualMemory");
	if (rockyFreeVirtualMemory == NULL) {
		printf("Failed to retrieve NtFreeVirtualMemory.\n");
		return;
	}

	
	SIZE_T regionSize = 0;  // Must be 0 for NtFreeVirtualMemory to free the entire region
	NTSTATUS status = rockyFreeVirtualMemory(GetCurrentProcess(),&pAddress,&regionSize,MEM_RELEASE);

	if (status != 0) {
		printf("Failed to deallocate memory.\n");
	}
	else {
		printf("Memory deallocated successfully.\n");
	}
}

/* [CUSTOM rockyPrintAllocated function used to retrieve and print data from allocated memory] */
void rockyPrintAllocated(const void* pAddress, size_t size) {
	if (pAddress == NULL) {
		rockyPrintColor(red, "Invalid Address");
		return;
	}

	const unsigned char* bytePtr = static_cast<const unsigned char*>(pAddress);
	rockyPrintColor(green, "raw payload:");
	for (size_t i = 0; i < size; ++i) {
		printf("%02X ", bytePtr[i]);
	}
	printf("\n");
}


























