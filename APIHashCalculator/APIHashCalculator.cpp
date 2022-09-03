#include <iostream>
#include <vector>
#include <unordered_map>
#include <Windows.h>

SIZE_T GetSizeOfStringA(LPSTR string) {

	SIZE_T totalSize = 0;

	for (SIZE_T i = 0; string[i] != '\0'; i++) {
		totalSize++;
	}

	return totalSize;
}


DWORD GetHashFromStringA(LPSTR string) {

	SIZE_T stringSize = GetSizeOfStringA(string);
	DWORD hash = 0x35;

	for (SIZE_T i = 0; i < stringSize; i++) {
		hash += (hash * 0xab10f29e + string[i]) & 0xffffff;
	}

	return hash;
}

std::unordered_map<LPCSTR, DWORD> CalculateHashes(const std::vector<LPCSTR>& apiFunctionList) {

	std::unordered_map<LPCSTR, DWORD> apiFunctionHashList = std::unordered_map<LPCSTR, DWORD>();

	for (auto apiFunction : apiFunctionList) {
		apiFunctionHashList[apiFunction] = GetHashFromStringA((LPSTR)apiFunction);
	}

	return apiFunctionHashList;

}

int main()
{

	std::vector<LPCSTR> apiFunctionList{ "LoadLibraryA", "GetProcAddress", "VirtualAlloc", "FlushInstructionCache",
											"FlushInstructionCache", "VirtualProtect", "KERNEL32.DLL" };
	std::unordered_map<LPCSTR, DWORD> apiHashList = CalculateHashes(apiFunctionList);

	for (auto apiFunction : apiHashList) {
		std::cout << apiFunction.first << ":0x" << std::hex << apiFunction.second << "\n";
	}
}

