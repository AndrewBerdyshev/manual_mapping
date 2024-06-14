#include "manual_mapping.h"

void ManualMap(const char* dll, const char* processName)
{
	const auto rawDLL = reinterpret_cast<uint64_t>(mylib::ReadFile(dll));
	if (!rawDLL) return;
	const auto processID = mylib::GetProcessID(processName);
	if (!processID) return;
	const auto process = OpenProcess(
		PROCESS_ALL_ACCESS, 
		FALSE, processID);
	if (!process) return;
	const auto imageBase = manual_mapping::UploadImage(process, rawDLL);
	if (!imageBase) return;
	manual_mapping::UploadRelocationStuff(process, imageBase);
}

uint64_t manual_mapping::UploadImage(const HANDLE process, const uint64_t rawDLL)
{
	const auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(rawDLL);
	const auto ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(rawDLL + dosHeader->e_lfanew);

	const auto imageBase = reinterpret_cast<uint64_t>(
		VirtualAllocEx(process, nullptr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!imageBase) return 0;

	auto section = IMAGE_FIRST_SECTION(ntHeader);
	for (size_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, section++)
	{
		WriteProcessMemory(process,
			reinterpret_cast<char*>(imageBase + section->VirtualAddress),
			reinterpret_cast<char*>(rawDLL + section->PointerToRawData),
			section->SizeOfRawData, nullptr);
	}

	WriteProcessMemory(process, reinterpret_cast<char*>(imageBase), reinterpret_cast<char*>(rawDLL), 
		PE_HEADER_SIZE(dosHeader), nullptr);
	return imageBase;
}

void manual_mapping::UploadRelocationStuff(const HANDLE process, const uint64_t imageBase)
{
	const auto funcSize = mylib::GetFuncSize(manual_mapping::RelocationStuff);
	const auto alloc = VirtualAllocEx(process, nullptr, funcSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!alloc) return;
	WriteProcessMemory(process, alloc, manual_mapping::RelocationStuff, funcSize, nullptr);

	const auto paramAlloc = VirtualAllocEx(process, nullptr, sizeof(RelocationStuffParams), 
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	RelocationStuffParams params;
	params.getProcAddress = GetProcAddress;
	params.loadLibraryA = LoadLibraryA;
	params.imageBase = imageBase;
	WriteProcessMemory(process, paramAlloc, &params, sizeof(params), nullptr);

	// Should be rewritten. no threads, please.
	//CreateRemoteThread(process, nullptr, NULL, (LPTHREAD_START_ROUTINE)alloc, paramAlloc, NULL, nullptr);
	threadhijacking::ThreadHijacking(process, alloc, paramAlloc);
}

void manual_mapping::RelocationStuff(RelocationStuffParams* params)
{
	const auto ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(
		params->imageBase + reinterpret_cast<IMAGE_DOS_HEADER*>(params->imageBase)->e_lfanew);

	// Relocating stuff.
	const auto relocationDetlta = static_cast<uint64_t>(params->imageBase - ntHeader->OptionalHeader.ImageBase);

	auto baseRelocationTableEntry = reinterpret_cast<IMAGE_BASE_RELOCATION*>
		(params->imageBase +
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	struct RELOCATION_INFO
	{
		uint16_t offset : 12;
		uint16_t type : 4;
	};

	for (; baseRelocationTableEntry->VirtualAddress;
		baseRelocationTableEntry =
		reinterpret_cast<IMAGE_BASE_RELOCATION*>(
			reinterpret_cast<uint64_t>(baseRelocationTableEntry) + baseRelocationTableEntry->SizeOfBlock))
	{
		const auto relocationCount =
			(baseRelocationTableEntry->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCATION_INFO);
		auto relocationInfoTableEntry =
			reinterpret_cast<RELOCATION_INFO*>(
				reinterpret_cast<uint64_t>(baseRelocationTableEntry) + sizeof(IMAGE_BASE_RELOCATION));
		for (size_t i = 0; i < relocationCount; i++, relocationInfoTableEntry++) {
			if (relocationInfoTableEntry->type == IMAGE_REL_BASED_DIR64) {
				auto relocFixAddress =
					reinterpret_cast<uint64_t*>(
						params->imageBase +
						baseRelocationTableEntry->VirtualAddress +
						relocationInfoTableEntry->offset);
				*relocFixAddress += relocationDetlta;
			}
		}
	}

	// Fixing imports.
	auto baseImportTableEntry =
		reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(params->imageBase +
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	for (; baseImportTableEntry->Characteristics; baseImportTableEntry++)
	{
		const auto moduleName = reinterpret_cast<char*>(params->imageBase + baseImportTableEntry->Name);
		const auto moduleHandle = params->loadLibraryA(moduleName);

		auto addressTableEntry = reinterpret_cast<IMAGE_THUNK_DATA*>(params->imageBase + baseImportTableEntry->FirstThunk);
		for (; addressTableEntry->u1.Function; addressTableEntry++)
		{
			const auto importedFunc = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(params->imageBase + 
				addressTableEntry->u1.AddressOfData);
			addressTableEntry->u1.Function = reinterpret_cast<uint64_t>(params->getProcAddress(moduleHandle, importedFunc->Name));
		}
	}

	// Calling tls-callbacks.
	if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto tlsTable =
			reinterpret_cast<IMAGE_TLS_DIRECTORY*>(params->imageBase +
				ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto tlsCallbackTableEntry =
			reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tlsTable->AddressOfCallBacks);
		for (; tlsCallbackTableEntry; tlsCallbackTableEntry++)
		{
			(*tlsCallbackTableEntry)(reinterpret_cast<void*>(params->imageBase), DLL_PROCESS_ATTACH, nullptr);
		}
	}

	// Calling DllMain.
	using DllMainPtr = BOOL(__stdcall*)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
	auto dllMain = reinterpret_cast<DllMainPtr>(params->imageBase + ntHeader->OptionalHeader.AddressOfEntryPoint);
	dllMain(reinterpret_cast<HINSTANCE>(params->imageBase), DLL_PROCESS_ATTACH, nullptr);
}