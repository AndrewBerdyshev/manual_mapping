#include <thread_hijacking.h>
#include <mylib.h>
#include <thread_hijacking.h>

void ManualMap(const char* dll, const char* processName);

#define PE_HEADER_SIZE(dosHeader) (\
dosHeader->e_lfanew + \
offsetof(IMAGE_NT_HEADERS, OptionalHeader) + \
reinterpret_cast<IMAGE_NT_HEADERS*>(rawDLL + dosHeader->e_lfanew)->FileHeader.SizeOfOptionalHeader + \
reinterpret_cast<IMAGE_NT_HEADERS*>(rawDLL + dosHeader->e_lfanew)->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER))

namespace manual_mapping
{
	uint64_t UploadImage(HANDLE process, uint64_t rawDLL);
	struct RelocationStuffParams
	{
		using LoadLibraryAFn = HMODULE(*)(LPCSTR lpLibFileName);
		LoadLibraryAFn loadLibraryA;
		using GetProcAddressFn = FARPROC(*)(HMODULE hModule, LPCSTR  lpProcName);
		GetProcAddressFn getProcAddress;
		uint64_t imageBase;
	};
	void RelocationStuff(RelocationStuffParams* params);
	void UploadRelocationStuff(const HANDLE process, const uint64_t imageBase);
}