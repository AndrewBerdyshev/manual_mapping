#include "manual_mapping.h"

void ManualMap(const char* dll, const char* processName)
{
	char fullPath[MAX_PATH];
	if (!GetFullPathNameA(dll, MAX_PATH, fullPath, nullptr)) return;
	const auto rawDLL = reinterpret_cast<uint64_t>(mylib::MyReadFile(fullPath));
	if (!rawDLL) return;

	const auto hijack = HandleHijacking(processName, PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE);
	if (!hijack.handle) return;
	auto process = new IOCTLProcess(hijack);
	auto thread = new ThreadProcess(hijack);

	const auto imageBase = manual_mapping::UploadImage(process, rawDLL);
	if (!imageBase) return;
	manual_mapping::UploadRelocationStuff(process, thread, imageBase);
	delete process;
	delete thread;
}

uint64_t manual_mapping::UploadImage(IOCTLProcess* process, const uint64_t rawDLL)
{
	const auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(rawDLL);
	const auto ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(rawDLL + dosHeader->e_lfanew);

	const auto imageBase = reinterpret_cast<uint64_t>(process->Alloc(ntHeader->OptionalHeader.SizeOfImage));
	if (!imageBase) return 0;

	auto section = IMAGE_FIRST_SECTION(ntHeader);
	for (size_t i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, section++)
	{
		process->Write(reinterpret_cast<char*>(imageBase + section->VirtualAddress),
			reinterpret_cast<uint8_t*>(rawDLL + section->PointerToRawData),
			section->SizeOfRawData);
	}

	process->Write(reinterpret_cast<void*>(imageBase), reinterpret_cast<uint8_t*>(rawDLL), PE_HEADER_SIZE(dosHeader));
	return imageBase;
}

void manual_mapping::UploadRelocationStuff(IOCTLProcess* process, ThreadProcess* thread, const uint64_t imageBase)
{
	const auto funcSize = mylib::GetFuncSize(manual_mapping::RelocationStuff);
	const auto alloc = process->Alloc(funcSize);
	if (!alloc) return;
	process->Write(alloc, reinterpret_cast<uint8_t*>(manual_mapping::RelocationStuff), funcSize);

	const auto paramAlloc = process->Alloc(sizeof(RelocationStuffParams));
	RelocationStuffParams params;
	// Addresses of these funcs are the same in all processes.
	params.getProcAddress = GetProcAddress;
	params.loadLibraryA = LoadLibraryA;
	params.imageBase = imageBase;
	process->Write(paramAlloc, reinterpret_cast<uint8_t*>(&params), sizeof(params));
	threadhijacking::ThreadHijacking(process, thread, alloc, paramAlloc);
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