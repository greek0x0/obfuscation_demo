#include "structures.h"
#include "functions.h"





void get_a_handle_on_module_example() {
	int str_ntdll_offsets_[] = { 39, 45, 29, 37, 37, 52, 29, 37, 37 };
	string deob_ntdll = rockyGetString(str_ntdll_offsets_, big_string, sizeof(str_ntdll_offsets_)).c_str();
	wstring deobfuscated_ntdll = stringToWstring(deob_ntdll);

	HMODULE rockyHandle = rockyGetModuleHandle(deobfuscated_ntdll.c_str());
	HMODULE rockyHandle2 = rockyGetModuleHandle2(deobfuscated_ntdll.c_str());

	rockyPrintColor(green, "Search for given DLL name and return its handle");
	rockyPrintColor(green, "rockyGetModuleHandle Function: 0x%p", rockyHandle);

	rockyPrintColor(green, "DLL enumeration using the head and the linked list's elements");
	rockyPrintColor(green, "rockyGetModuleHandle2 Function: 0x%p", rockyHandle2);

}

void next_function() {
	rockyPrintColor(red, "[#] Press <Enter> To Next ... ");
	getchar();
}

void allocate_memory_bytes_example() {
	
	/* [ PAYLOAD EXAMPLE OF .DATA] */
	/* .DATA SECTION PAYLOAD::: NOTE: Payloads that are assigned like this are saved in the .data section of the PE Executable */
	unsigned char payload[] = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00 };
	size_t payload_size = sizeof(payload);


	/* [ PAYLOAD EXAMPLE OF .RDATA] */
	/* const unsigned char Rdata_RawData[] = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00  }; */


	void* pointer_to_payload = rockyAlloc(payload, payload_size);
	if (pointer_to_payload != NULL) {
		printf("Allocated success, Raw payload example:\n");
		rockyPrintAllocated(pointer_to_payload, payload_size);
		rockyDealloc(pointer_to_payload);
	}
	else {
		rockyPrintColor(red, "Failed to allocate raw payload");
	}
}


void allocate_memory_string_example() {
	const char* MyString = "Hello World";
	
	void* pointer_to_string_address = rockyAlloc(MyString);

	if (pointer_to_string_address != NULL) {
		printf("String data:\n");
		rockyPrintAllocated(pointer_to_string_address, strlen(MyString) + 1); // NULL Terminator
		rockyDealloc(pointer_to_string_address);
	}
	else {
		rockyPrintColor(red, "Failed to allocate string to memory");
	}
}

void load_a_dll_example() {
	HMODULE hModule = (HMODULE)rockyLoadLibrary(L"user32.dll");
	if (hModule) {
		rockyPrintColor(green, "Successful loaded DLL");
	}
	else {
		rockyPrintColor(red, "Failed to load DLL");
	}

}



void run_examples() {

	get_a_handle_on_module_example();
	
	next_function();

	allocate_memory_bytes_example();

	next_function();

	allocate_memory_string_example();

	next_function();

	load_a_dll_example();
}


void obfuscator() {

	rockyPrintColor(green, "Starting obfuscation");

	/* Obfuscate a string */
	//char obfuscated_string_test[] = "Hello World";
	//char ntdll_string[] = "NTDLL.DLL";
	//rockyObfuscation(big_string, ntdll_string);

	/* Need to be obfuscated*/
	char str_LdrGetProcedureAddress[] = "LdrGetProcedureAddress";
	char str_LdrLoadDll[] = "LdrLoadDll";
	char str_NtAllocateVirtualMemory[] = "NtAllocateVirtualMemory";
	char str_NtFreeVirtualMemory[] = "NtFreeVirtualMemory";
	/* Obfuscated string */
	rockyObfuscation(big_string, str_NtFreeVirtualMemory);
	/* Retrive obfuscated string */

}

int main() {
	//get_a_handle_on_module_example();
	run_examples();
	//obfuscator();

}