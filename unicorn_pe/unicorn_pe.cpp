#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <BlackBone/Process/Process.h>
#include <BlackBone/ManualMap/MMap.h>

#include <iostream>
#include <sstream>
#include <fstream>
#include <functional>
#include <vector>
#include <set>
#include <intrin.h>

#include "buffer.h"
#include "encode.h"
#include "nativestructs.h"
#include "ucpe.h"
#include "emuapi.h"

#pragma comment(lib,"ntdll.lib")

std::ostream *outs;

extern "C"
{
	NTSYSAPI
		PIMAGE_NT_HEADERS
		NTAPI
		RtlImageNtHeader(IN PVOID BaseAddress);

	NTSYSAPI
		PVOID
		NTAPI
		RtlImageDirectoryEntryToData(
			PVOID BaseAddress,
			BOOLEAN MappedAsImage,
			USHORT Directory,
			PULONG Size
		);
}

uint64_t EmuReadReturnAddress(uc_engine *uc);
bool EmuReadNullTermUnicodeString(uc_engine *uc, uint64_t address, std::wstring &str);
bool EmuReadNullTermString(uc_engine *uc, uint64_t address, std::string &str);

blackbone::LoadData ManualMapCallback(blackbone::CallbackType type, void* context, blackbone::Process& /*process*/, const blackbone::ModuleData& modInfo)
{
	PeEmulation *ctx = (PeEmulation *)context;
	if (type == blackbone::ImageCallback)
	{
		uint64_t desiredBase = ctx->m_LoadModuleBase;
		uint64_t desiredNextLoadBase = PAGE_ALIGN_64k((uint64_t)ctx->m_LoadModuleBase + (uint64_t)modInfo.size + 0x10000ull);
		ctx->m_LoadModuleBase = desiredNextLoadBase;

		return blackbone::LoadData(blackbone::MT_Default, blackbone::Ldr_None, desiredBase);
	}
	else if (type == blackbone::PostCallback)
	{
		ctx->MapImageToEngine(modInfo.name, (PVOID)modInfo.imgPtr, modInfo.size, modInfo.baseAddress, modInfo.entryPoint);
	}

	return blackbone::LoadData(blackbone::MT_Default, blackbone::Ldr_None, 0);
};

void PeEmulation::AddAPIEmulation(FakeAPI_t *r, void *callback, int argsCount)
{
	r->EmuCallback = callback;

	if (callback)
	{
		uc_err err;

		unsigned char code[] = "\xC3";
		err = uc_mem_write(m_uc, r->VirtualAddress, code, sizeof(code));
	}
}

bool PeEmulation::RegisterAPIEmulation(const std::wstring &DllName, const char *ProcedureName, void *callback, int argsCount)
{
	FakeAPI_t *r = NULL;
	for (size_t i = 0; i < m_FakeModules.size(); ++i)
	{
		auto &m = m_FakeModules[i];
		if (!_wcsicmp(m->DllName.c_str(), DllName.c_str()))
		{
			for (size_t j = 0; j < m->FakeAPIs.size(); ++j)
			{
				if (m->FakeAPIs[j].ProcedureName == ProcedureName)
				{
					AddAPIEmulation(&m->FakeAPIs[j], callback, argsCount);
					return true;
				}
			}
			*outs << "failed to register API emulation for " << ProcedureName << "\n";
			return false;
		}
	}
	return false;
}

bool PeEmulation::FindAddressInRegion(ULONG64 address, std::stringstream &RegionName)
{
	for (size_t i = 0; i < m_FakeModules.size(); ++i)
	{
		if (address >= m_FakeModules[i]->ImageBase && address < m_FakeModules[i]->ImageBase + m_FakeModules[i]->ImageSize)
		{
			std::string dllname;
			UnicodeToANSI(m_FakeModules[i]->DllName, dllname);
			RegionName << dllname << "+" << std::hex << (address - m_FakeModules[i]->ImageBase);
			return true;
		}
	}

	if (address >= m_StackBase && address < m_StackEnd)
	{
		RegionName << "StackBase+" << std::hex << (address - m_StackBase);
		return true;
	}

	if (address >= m_HeapBase && address < m_HeapEnd)
	{
		RegionName << "HeapBase+" << std::hex << (address - m_HeapBase);
		return true;
	}

	if (!m_IsKernel)
	{
		if (address >= m_PebBase && address < m_PebEnd)
		{
			RegionName << "Peb+" << std::hex << (address - m_PebBase);
			return true;
		}

		if (address >= m_TebBase && address < m_TebEnd)
		{
			RegionName << "Teb+" << std::hex << (address - m_TebBase);
			return true;
		}
	}
	else
	{
		if (address >= m_DriverObjectBase && address < m_DriverObjectBase + sizeof(DRIVER_OBJECT))
		{
			RegionName << "DriverObject+" << std::hex << (address - m_DriverObjectBase);
			return true;
		}
	}

	if (address >= m_KSharedUserDataBase && address < m_KSharedUserDataEnd)
	{
		RegionName << "KSharedUserData+" << std::hex << (address - m_KSharedUserDataBase);
		return true;
	}
	
	return false;
}

bool PeEmulation::FindAPIByAddress(ULONG64 address, std::wstring &DllName, FakeAPI_t **api)
{
	for (size_t i = 0; i < m_FakeModules.size(); ++i)
	{
		auto &m = m_FakeModules[i];
		if (address >= m->ImageBase && address < m->ImageBase + m->ImageSize)
		{
			DllName = m->DllName;

			for (size_t j = 0; j < m->FakeAPIs.size(); ++j)
			{
				auto r = &m->FakeAPIs[j];
				if (r->VirtualAddress == address)
				{
					*api = r;
					return true;
				}
			}

			break;
		}
	}
	return false;
}

bool PeEmulation::FindSectionByAddress(ULONG64 address, FakeSection_t **section)
{
	for (size_t i = 0; i < m_FakeModules.size(); ++i)
	{
		auto &m = m_FakeModules[i];
		if (address >= m->ImageBase && address < m->ImageBase + m->ImageSize)
		{
			for (size_t j = 0; j < m->FakeSections.size(); ++j)
			{
				auto r = &m->FakeSections[j];
				if (address >= m->ImageBase + r->SectionBase && address < m->ImageBase + r->SectionBase + r->SectionSize)
				{
					*section = r;
					return true;
				}
			}

			break;
		}
	}
	return false;
}

bool PeEmulation::FindModuleByAddress(ULONG64 address, ULONG64 &DllBase)
{
	if (address >= m_ImageBase && address < m_ImageEnd)
	{
		DllBase = m_ImageBase;
		return true;
	}

	for (size_t i = 0; i < m_FakeModules.size(); ++i)
	{
		auto &m = m_FakeModules[i];
		if (address >= m->ImageBase && address < m->ImageBase + m->ImageSize)
		{
			DllBase = m->ImageBase;
			return true;
		}
	}
	return false;
}

ULONG64 PeEmulation::LdrGetProcAddress(ULONG64 ImageBase, const char *ProcedureName)
{
	if (!strcmp(ProcedureName, "FlsAlloc"))
	{
		return 0;
	}
	if (!strcmp(ProcedureName, "FlsSetValue"))
	{
		return 0;
	}
	if (!strcmp(ProcedureName, "FlsFree"))
	{
		return 0;
	}
	
	for (size_t i = 0; i < m_FakeModules.size(); ++i)
	{
		auto &m = m_FakeModules[i];
		if (m->ImageBase == ImageBase)
		{
			for (size_t j = 0; j < m->FakeAPIs.size(); ++j)
			{
				auto &r = m->FakeAPIs[j];
				if (r.ProcedureName == ProcedureName)
				{
					return r.VirtualAddress;
				}
			}
		}
	}

	return 0;
}

VOID PeEmulation::LdrResolveExportTable(FakeModule_t *module, PVOID ImageBase, ULONG64 MappedBase)
{
	DWORD uExportSize = 0;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
		RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &uExportSize);

	if (!pImageExportDirectory)
		return;

	DWORD dwNumberOfNames = (DWORD)(pImageExportDirectory->NumberOfNames);
	DWORD *pAddressOfFunction = (DWORD*)((PUCHAR)ImageBase + pImageExportDirectory->AddressOfFunctions);
	DWORD *pAddressOfNames = (DWORD*)((PUCHAR)ImageBase + pImageExportDirectory->AddressOfNames);
	WORD *pAddressOfNameOrdinals = (WORD*)((PUCHAR)ImageBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (size_t i = 0; i < dwNumberOfNames; i++)
	{
		char *strFunction = (char *)((PUCHAR)ImageBase + pAddressOfNames[i]);

		DWORD functionRva = pAddressOfFunction[pAddressOfNameOrdinals[i]];
		//forward
		if ((PUCHAR)ImageBase + functionRva >= (PUCHAR)pImageExportDirectory &&
			(PUCHAR)ImageBase + functionRva < (PUCHAR)pImageExportDirectory + uExportSize)
		{
			char *strForward = (char *)ImageBase + functionRva;
			char*strForwardFunction = strchr(strForward, '.');
			if (strForwardFunction)
			{
				std::string strForwardDll(strForward, strForwardFunction - strForward);
				strForwardDll += ".dll";
				ULONG64 ForwardDllBase = 0;
				std::wstring wszForwardDll;
				ANSIToUnicode(strForwardDll, wszForwardDll);
				if (NT_SUCCESS(LdrFindDllByName(wszForwardDll, &ForwardDllBase, NULL, true)))
				{
					ULONG64 ForwardFunction = LdrGetProcAddress(ForwardDllBase, strForwardFunction + 1);
					if (ForwardFunction)
						module->FakeAPIs.emplace_back(strFunction, ForwardFunction);
				}
			}
		}
		else
		{
			module->FakeAPIs.emplace_back(strFunction, MappedBase + functionRva);
		}
	}
}

NTSTATUS PeEmulation::LdrFindDllByName(const std::wstring &DllName, ULONG64 *ImageBase, ULONG *ImageSize, bool LoadIfNotExist)
{
	using namespace blackbone;

	std::wstring newDllName = DllName;

	if (!_wcsicmp(newDllName.c_str(), L"NTOSKRNL.DLL"))
	{
		newDllName = L"NTOSKRNL.EXE";
	}

	if (newDllName.find(L".") == std::wstring::npos)
	{
		if(m_IsKernel)
			newDllName += L".SYS";
		else
			newDllName += L".DLL";
	}

	auto moduleptr = thisProc.modules().GetModule(newDllName, ManualOnly, mt_default);

	if (moduleptr)
	{
		if (ImageBase)
			*ImageBase = moduleptr->baseAddress;
		if (ImageSize)
			*ImageSize = moduleptr->size;

		return STATUS_SUCCESS;
	}

	if(LoadIfNotExist)
		return LdrLoadDllByName(newDllName, ImageBase, ImageSize);

	return STATUS_OBJECT_NAME_NOT_FOUND;
}

NTSTATUS PeEmulation::LdrLoadDllByName(const std::wstring &DllName, ULONG64 *ImageBase, ULONG *ImageSize)
{
	using namespace blackbone;

	auto MapResult = thisProc.mmap().MapImage(DllName,
		ManualImports | NoSxS | NoDelayLoad| NoExceptions | NoTLS | NoExec,
		ManualMapCallback, this);

	if (!MapResult.success())
	{
		printf("LdrLoadDllByName failed to MapImage %ws, status %08X\n", DllName.c_str(), MapResult.status);
		return MapResult.status;
	}

	return STATUS_SUCCESS;
}

static void EmuUnknownAPI(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

void PeEmulation::MapImageToEngine(const std::wstring &ImageName, PVOID ImageBase, ULONG ImageSize, ULONG64 MappedBase, ULONG64 EntryPoint)
{
	FakeModule_t *mod = new FakeModule_t(MappedBase, ImageSize, EntryPoint, ImageName);

	if (!_wcsicmp(ImageName.c_str(), L"ntoskrnl.exe"))
		mod->Priority = 100;
	else if (!_wcsicmp(ImageName.c_str(), L"hal.dll"))
		mod->Priority = 99;

	auto ExceptionTable = RtlImageDirectoryEntryToData(ImageBase,
		TRUE,
		IMAGE_DIRECTORY_ENTRY_EXCEPTION,
		&mod->ExceptionTableSize);

	mod->ExceptionTable = MappedBase + ((PUCHAR)ExceptionTable - (PUCHAR)ImageBase);

	RtlInsertInvertedFunctionTable(&m_PsInvertedFunctionTable, MappedBase, ImageBase, ImageSize);

	m_FakeModules.push_back(mod);

	LdrResolveExportTable(mod, ImageBase, MappedBase);

	uint64_t image_base = (uint64_t)MappedBase;
	uint64_t image_end = PAGE_ALIGN_64(image_base + ImageSize);

	if (image_end != image_base)
		uc_mem_map(m_uc, image_base, (size_t)(image_end - image_base), UC_PROT_READ);
	else
		uc_mem_map(m_uc, image_base, PAGE_SIZE, UC_PROT_READ);

	uc_mem_write(m_uc, image_base, ImageBase, ImageSize);

	auto ntheader = (PIMAGE_NT_HEADERS)RtlImageNtHeader(ImageBase);

	DWORD SectionAlignment;

	if (ntheader->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		auto ntheader64 = (PIMAGE_NT_HEADERS64)ntheader;
		SectionAlignment = ntheader64->OptionalHeader.SectionAlignment;
	}
	else
	{
		SectionAlignment = ntheader->OptionalHeader.SectionAlignment;
	}

	auto SectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)ntheader + sizeof(ntheader->Signature) + \
		sizeof(ntheader->FileHeader) + ntheader->FileHeader.SizeOfOptionalHeader);

	for (WORD i = 0; i < ntheader->FileHeader.NumberOfSections; i++)
	{
		int prot = UC_PROT_READ;
		if (SectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			prot |= UC_PROT_EXEC;
		if (SectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			prot |= UC_PROT_WRITE;

		auto SectionSize = AlignSize(
			max(SectionHeader[i].Misc.VirtualSize, SectionHeader[i].SizeOfRawData),
			SectionAlignment);

		uc_mem_protect(m_uc, image_base + SectionHeader[i].VirtualAddress, SectionSize, prot);

		if (SectionHeader[i].Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))
		{
			bool bIsUnknownSection = (0 == memcmp((char *)SectionHeader[i].Name, ".text\0\0\0", 8)
				|| 0 == memcmp((char *)SectionHeader[i].Name, "INIT\0\0\0\0", 8)
				|| 0 == memcmp((char *)SectionHeader[i].Name, "PAGE\0\0\0\0", 8)) ? false : true;

			mod->FakeSections.emplace_back(SectionHeader[i].VirtualAddress, SectionSize, (char *)SectionHeader[i].Name, bIsUnknownSection);

			uc_hook trace3;
			uc_hook_add(m_uc, &trace3, UC_HOOK_CODE, EmuUnknownAPI,
				this, image_base + SectionHeader[i].VirtualAddress,
				image_base + SectionHeader[i].VirtualAddress + SectionSize - 1);
		}
	}
}

static void CodeCallback(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;
	
	/*uc_reg_read(uc, UC_X86_REG_EFLAGS, &ctx->m_InitReg.EFlags);
	ctx->m_InitReg.EFlags |= (1 << 8);
	uc_reg_write(uc, UC_X86_REG_EFLAGS, &ctx->m_InitReg.EFlags);*/

	ctx->FlushMemMapping();

	if (ctx->m_DisplayDisasm)
	{
		unsigned char codeBuffer[15];
		uc_mem_read(uc, address, codeBuffer, size);

		cs_insn insn;
		memset(&insn, 0, sizeof(insn));

		uint64_t virtualBase = address;
		uint8_t *code = codeBuffer;
		size_t codeSize = size;
		cs_disasm_iter(ctx->m_cs, (const uint8_t **)&code, &codeSize, &virtualBase, &insn);

		*outs << std::hex << address << "\t\t\t" << insn.mnemonic << "\t\t" << insn.op_str << "\n";
	}

	ctx->m_LastRip = address;
	ctx->m_ExecCodeCount++;

	if (ctx->m_ExecCodeCount % 100000 == 0)
	{
		outs->flush();
	}
}

static void IntrCallback(uc_engine *uc, int exception, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;
	*outs << "exception #" << std::hex << exception << "\n";

	if (exception == EXCP01_DB)
	{
		ctx->m_LastException = STATUS_SINGLE_STEP;
	}
	else if (exception == EXCP03_INT3)
	{
		ctx->m_LastException = STATUS_BREAKPOINT;
	}
	else
	{
		ctx->m_LastException = STATUS_SUCCESS;
	}
	uc_emu_stop(uc);
}

static bool InvalidRwxCallback(uc_engine *uc, uc_mem_type type,
	uint64_t address, int size, int64_t value, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	switch (type) {
	case UC_MEM_FETCH_PROT: {
		uint64_t rip;
		uc_reg_read(uc, UC_X86_REG_RIP, &rip);

		std::stringstream region;
		if (ctx->FindAddressInRegion(address, region))
			*outs << "UC_MEM_FETCH_PROT from " << region.str() << "\n";
		else
			*outs << "UC_MEM_FETCH_PROT from " << address << "\n";

		std::stringstream region2;
		if (ctx->FindAddressInRegion(rip, region2))
			*outs << "UC_MEM_FETCH_PROT rip at " << region2.str() << "\n";
		else
			*outs << "UC_MEM_FETCH_PROT rip at " << rip << "\n";

		uc_emu_stop(uc);
		break;
	}
	case UC_MEM_WRITE_PROT: {
		uint64_t rip;
		uc_reg_read(uc, UC_X86_REG_RIP, &rip);

		std::stringstream region;
		if (ctx->FindAddressInRegion(address, region))
			*outs << "UC_MEM_WRITE_PROT from " << region.str() << "\n";
		else
			*outs << "UC_MEM_WRITE_PROT from " << address << "\n";

		std::stringstream region2;
		if (ctx->FindAddressInRegion(rip, region2))
			*outs << "UC_MEM_WRITE_PROT rip at " << region2.str() << "\n";
		else
			*outs << "UC_MEM_WRITE_PROT rip at " << rip << "\n";

		uc_emu_stop(uc);
		break;
	}
	case UC_MEM_FETCH_UNMAPPED: {
		uint64_t rip;
		uc_reg_read(uc, UC_X86_REG_RIP, &rip);

		std::stringstream region;
		if (ctx->FindAddressInRegion(address, region))
			*outs << "UC_MEM_FETCH_UNMAPPED from " << region.str() << "\n";
		else
			*outs << "UC_MEM_FETCH_UNMAPPED from " << address << "\n";

		std::stringstream region2;
		if (ctx->FindAddressInRegion(rip, region2))
			*outs << "UC_MEM_FETCH_UNMAPPED rip at " << region2.str() << "\n";
		else
			*outs << "UC_MEM_FETCH_UNMAPPED rip at " << rip << "\n";

		uc_emu_stop(uc);
		break;
	}
	case UC_MEM_READ_UNMAPPED: {
		uint64_t rip;
		uc_reg_read(uc, UC_X86_REG_RIP, &rip);

		std::stringstream region;
		if (ctx->FindAddressInRegion(address, region))
			*outs << "UC_MEM_READ_UNMAPPED from " << region.str() << "\n";
		else
			*outs << "UC_MEM_READ_UNMAPPED from " << address << "\n";

		std::stringstream region2;
		if (ctx->FindAddressInRegion(rip, region2))
			*outs << "UC_MEM_READ_UNMAPPED rip at " << region2.str() << "\n";
		else
			*outs << "UC_MEM_READ_UNMAPPED rip at " << rip << "\n";

		uc_emu_stop(uc);
		break;
	}
	case UC_MEM_WRITE_UNMAPPED: {
		uint64_t rip;
		uc_reg_read(uc, UC_X86_REG_RIP, &rip);

		std::stringstream region;
		if (ctx->FindAddressInRegion(address, region))
			*outs << "UC_MEM_WRITE_UNMAPPED from " << region.str() << "\n";
		else
			*outs << "UC_MEM_WRITE_UNMAPPED from " << address << "\n";

		std::stringstream region2;
		if (ctx->FindAddressInRegion(rip, region2))
			*outs << "UC_MEM_WRITE_UNMAPPED rip at " << region2.str() << "\n";
		else
			*outs << "UC_MEM_WRITE_UNMAPPED rip at " << rip << "\n";

		uc_emu_stop(uc);
		break;
	}
	}
	return false;
}

static void RwxCallback(uc_engine *uc, uc_mem_type type,
	uint64_t address, int size, int64_t value, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	switch (type) {
	case UC_MEM_READ: {
		if (ctx->m_BoundCheck)
		{
			std::stringstream region;
			if (!ctx->FindAddressInRegion(address, region))
			{
				*outs << "UC_MEM_READ out of region\n";

				uint64_t rip;
				uc_reg_read(uc, UC_X86_REG_RIP, &rip);
				if (ctx->FindAddressInRegion(rip, region))
					*outs << "UC_MEM_READ rip at " << region.str() << "\n";

				uc_emu_stop(uc);
			}
		}

		break;
	}
	case UC_MEM_WRITE: {
		if (ctx->m_BoundCheck)
		{
			std::stringstream region;
			if (!ctx->FindAddressInRegion(address, region))
			{
				*outs << "UC_MEM_WRITE out of region\n";

				uint64_t rip;
				uc_reg_read(uc, UC_X86_REG_RIP, &rip);
				if (ctx->FindAddressInRegion(rip, region))
					*outs << "UC_MEM_WRITE rip at " << region.str() << "\n";

				uc_emu_stop(uc);
			}
		}
		if (ctx->WriteMemMapping(address, value, size))
		{
			//*outs << "write to mapping address " << address << "\n";
		}

		break;
	}
	case UC_MEM_FETCH: {


		break;
	}
	}
}

static void EmuUnknownAPI(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;
	
	std::wstring DllName;
	FakeAPI_t *api = NULL;

	uint64_t currentModule = 0;
	ctx->FindModuleByAddress(address, currentModule);

	if (currentModule != ctx->m_LastRipModule)
	{
		if (ctx->m_LastRipModule == ctx->m_ImageBase)
		{
			if (ctx->FindAPIByAddress(address, DllName, &api))
			{
				if (!api->EmuCallback)
				{
					std::string aDllName;
					UnicodeToANSI(DllName, aDllName);
					*outs << "API emulation callback not registered: " << aDllName << "!" << api->ProcedureName << "\n";
					auto retaddr = EmuReadReturnAddress(uc);
					if (retaddr >= ctx->m_ImageBase && retaddr < ctx->m_ImageEnd)
						*outs << "called from imagebase+0x" << std::hex << (ULONG)(retaddr - ctx->m_ImageBase) << "\n";
					uc_emu_stop(uc);
				}
				else
				{
					void(*callback)(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
						= (decltype(callback))api->EmuCallback;

					callback(uc, address, size, user_data);
				}
			}
			else
			{
				*outs << "unknown API called\n";
				auto retaddr = EmuReadReturnAddress(uc);
				if (retaddr >= ctx->m_ImageBase && retaddr < ctx->m_ImageEnd)
					*outs << "called from imagebase+0x" << std::hex << (ULONG)(retaddr - ctx->m_ImageBase) << "\n";
				uc_emu_stop(uc);
			}
		}
		ctx->m_LastRipModule = currentModule;
	}	
	else if(currentModule != ctx->m_ImageBase)
	{
		if (ctx->FindAPIByAddress(address, DllName, &api))
		{
			_CrtDbgBreak();
		}
	}

	if(currentModule == ctx->m_ImageBase && ctx->m_IsPacked && !ctx->m_ImageRealEntry)
	{
		FakeSection_t *section = NULL;
		if (ctx->FindSectionByAddress(address, &section) && !section->IsUnknownSection)
		{
			ctx->m_ImageRealEntry = address;
		}
	}
}

static void init_descriptor64(SegmentDesctiptorX64 *desc, uint64_t base, uint64_t limit, bool is_code, bool is_long_mode)
{
	desc->descriptor.all = 0;  //clear the descriptor
	desc->descriptor.fields.base_low = base;
	desc->descriptor.fields.base_mid = (base >> 16) & 0xff;
	desc->descriptor.fields.base_high = base >> 24;
	desc->base_upper32 = base >> 32;

	if (limit > 0xfffff) {
		limit >>= 12;
		desc->descriptor.fields.gran = 1;
	}

	desc->descriptor.fields.limit_low = limit & 0xffff;
	desc->descriptor.fields.limit_high = limit >> 16;

	desc->descriptor.fields.dpl = 0;
	desc->descriptor.fields.present = 1;
	desc->descriptor.fields.db = 1;   //64 bit
	desc->descriptor.fields.type = is_code ? 0xb : 3;
	desc->descriptor.fields.system = 1;  //code or data
	desc->descriptor.fields.l = is_long_mode ? 1 : 0;
}

typedef struct _KPCR
{
	SegmentDesctiptorX64 gdt[8];
}KPCR;

void PeEmulation::InitProcessorState()
{
	uc_x86_mmr gdtr;

	uint64_t kpcr_base = 0xfffff00000000000ull;
	
	KPCR kpcr;

	memset(&kpcr, 0, sizeof(KPCR));

	gdtr.base = kpcr_base + offsetof(KPCR, gdt);
	gdtr.limit = sizeof(kpcr.gdt) - 1;

	init_descriptor64(&kpcr.gdt[1], 0, 0xffffffffffffffff, true, true);
	init_descriptor64(&kpcr.gdt[2], 0, 0xffffffffffffffff, false, true);

	auto err = uc_mem_map(m_uc, kpcr_base, PAGE_SIZE, UC_PROT_READ);
	err = uc_mem_write(m_uc, kpcr_base, &kpcr, sizeof(KPCR));
	err = uc_reg_write(m_uc, UC_X86_REG_GDTR, &gdtr);
	
	SegmentSelector cs = {0};
	cs.fields.index = 1;
	uc_reg_write(m_uc, UC_X86_REG_CS, &cs.all);
	
	SegmentSelector ds = { 0 };
	ds.fields.index = 2;
	uc_reg_write(m_uc, UC_X86_REG_DS, &ds.all);

	SegmentSelector ss = { 0 };
	ds.fields.index = 2;
	uc_reg_write(m_uc, UC_X86_REG_SS, &ss.all);

	SegmentSelector es = { 0 };
	ds.fields.index = 2;
	uc_reg_write(m_uc, UC_X86_REG_ES, &es.all);

	SegmentSelector gs = { 0 };
	gs.fields.index = 2;
	uc_reg_write(m_uc, UC_X86_REG_GS, &gs.all);

	FlagRegister eflags = {0};
	eflags.fields.id = 1;
	eflags.fields.intf = 1;
	eflags.fields.reserved1 = 1;

	uc_reg_write(m_uc, UC_X86_REG_EFLAGS, &eflags.all);

	uint64_t cr8 = 0;
	uc_reg_write(m_uc, UC_X86_REG_CR8, &cr8);
}

void PeEmulation::InitTebPeb()
{
	PEB peb = { 0 };

	m_PebBase = 0x90000ull;
	m_PebEnd = m_PebBase + AlignSize(sizeof(PEB), PAGE_SIZE);

	uc_mem_map(m_uc, m_PebBase, m_PebEnd - m_PebBase, UC_PROT_READ);
	uc_mem_write(m_uc, m_PebBase, &peb, sizeof(PEB));

	m_TebBase = 0x80000ull;
	m_TebEnd = m_TebBase + AlignSize(sizeof(TEB), PAGE_SIZE);

	TEB teb = { 0 };

	teb.ProcessEnvironmentBlock = (PPEB)m_PebBase;

	uc_mem_map(m_uc, m_TebBase, m_TebEnd - m_TebBase, UC_PROT_READ);
	uc_mem_write(m_uc, m_TebBase, &teb, sizeof(TEB));

	uc_x86_msr msr;
	msr.rid = (uint32_t)Msr::kIa32GsBase;
	msr.value = m_TebBase;

	uc_reg_write(m_uc, UC_X86_REG_MSR, &msr);
}

void PeEmulation::InitKTHREAD()
{
	//todo
	m_KThreadBase = HeapAlloc(1234);

	uc_x86_msr msr;
	msr.rid = (uint32_t)Msr::kIa32GsBase;
	msr.value = m_KThreadBase;

	uc_reg_write(m_uc, UC_X86_REG_MSR, &msr);
}

void PeEmulation::SortModuleList()
{
	std::sort(m_FakeModules.begin(), m_FakeModules.end(),
		[](const FakeModule_t *value1, const FakeModule_t *value2)
	{
		return value1->Priority > value2->Priority;
	});
}

void PeEmulation::InsertTailList(
	IN ULONG64 ListHeadAddress,
	IN ULONG64 EntryAddress
)
{
	PLIST_ENTRY Blink;

	//Blink = ListHead->Blink;
	uc_mem_read(m_uc, ListHeadAddress + offsetof(LIST_ENTRY, Blink), &Blink, sizeof(Blink));
	
	//Entry->Flink = (PLIST_ENTRY)ListHeadAddress;
	
	uc_mem_write(m_uc, EntryAddress + offsetof(LIST_ENTRY, Flink), &ListHeadAddress, sizeof(ListHeadAddress));
	
	//Entry->Blink = Blink;

	uc_mem_write(m_uc, EntryAddress + offsetof(LIST_ENTRY, Blink), &Blink, sizeof(Blink));

	//Blink->Flink = (PLIST_ENTRY)EntryAddress;

	uc_mem_write(m_uc, (uint64_t)Blink + offsetof(LIST_ENTRY, Flink), &EntryAddress, sizeof(EntryAddress));

	//ListHead->Blink = (PLIST_ENTRY)EntryAddress;

	uc_mem_write(m_uc, ListHeadAddress + offsetof(LIST_ENTRY, Blink), &EntryAddress, sizeof(EntryAddress));
}

void PeEmulation::InitPsLoadedModuleList()
{
	m_PsLoadedModuleListBase = HeapAlloc(sizeof(LIST_ENTRY));

	LIST_ENTRY PsLoadedModuleList = { 0 };
	PsLoadedModuleList.Blink = PsLoadedModuleList.Flink = (PLIST_ENTRY)m_PsLoadedModuleListBase;

	uc_mem_write(m_uc, m_PsLoadedModuleListBase, &PsLoadedModuleList, sizeof(PsLoadedModuleList));

	for (size_t i = 0; i < m_FakeModules.size(); ++i)
	{
		auto LdrEntryBase = HeapAlloc(sizeof(KLDR_DATA_TABLE_ENTRY));

		KLDR_DATA_TABLE_ENTRY LdrEntry = { 0 };
		LdrEntry.DllBase = (PVOID)m_FakeModules[i]->ImageBase;
		LdrEntry.LoadCount = 1;
		LdrEntry.EntryPoint = (PVOID)m_FakeModules[i]->ImageEntry;
		LdrEntry.SizeOfImage = m_FakeModules[i]->ImageSize;
		
		auto fullname = L"\\SystemRoot\\system32\\drivers\\" + m_FakeModules[i]->DllName;		
		LdrEntry.FullDllName.Length = (USHORT)fullname.length() * sizeof(WCHAR);
		LdrEntry.FullDllName.MaximumLength = ((USHORT)fullname.length() + 1) * sizeof(WCHAR);
		auto FullDllNameBase = HeapAlloc(LdrEntry.FullDllName.MaximumLength);
		LdrEntry.FullDllName.Buffer = (PWSTR)FullDllNameBase;
		
		LdrEntry.BaseDllName.Length = (USHORT)fullname.length() - (_countof(L"\\SystemRoot\\system32\\drivers\\") - 1) * sizeof(WCHAR);
		LdrEntry.BaseDllName.MaximumLength = ((USHORT)fullname.length() + 1 - (_countof(L"\\SystemRoot\\system32\\drivers\\") - 1)) * sizeof(WCHAR);
		auto BaseDllNameBase = FullDllNameBase + (_countof(L"\\SystemRoot\\system32\\drivers\\") - 1) * sizeof(WCHAR);
		LdrEntry.BaseDllName.Buffer = (PWSTR)BaseDllNameBase;

		LdrEntry.ExceptionTable = (PVOID)m_FakeModules[i]->ExceptionTable;
		LdrEntry.ExceptionTableSize = m_FakeModules[i]->ExceptionTableSize;

		uc_mem_write(m_uc, FullDllNameBase, fullname.data(), LdrEntry.FullDllName.MaximumLength);

		uc_mem_write(m_uc, LdrEntryBase, &LdrEntry, sizeof(LdrEntry));

		if (m_FakeModules[i]->ImageBase == m_ImageBase)
		{
			m_DriverLdrEntry = LdrEntryBase;
			m_MainModuleIndex = (int)i;
		}

		InsertTailList(m_PsLoadedModuleListBase, LdrEntryBase);
	}
}

void PeEmulation::InitDriverObject()
{
	m_DriverObjectBase = HeapAlloc(sizeof(DRIVER_OBJECT));

	DRIVER_OBJECT DriverObject = { 0 };
	DriverObject.DriverSize = (ULONG)(m_ImageEnd - m_ImageBase);
	DriverObject.DriverStart = (PVOID)m_ImageBase;
	DriverObject.DriverInit = (PVOID)m_ImageEntry;
	DriverObject.Size = sizeof(DRIVER_OBJECT);
	DriverObject.DriverSection = (PVOID)m_DriverLdrEntry;

	uc_mem_write(m_uc, m_DriverObjectBase, &DriverObject, sizeof(DriverObject));
}

void PeEmulation::InitKSharedUserData()
{
	if (m_IsKernel)
	{
		m_KSharedUserDataBase = 0xfffff78000000000ull;
		m_KSharedUserDataEnd = 0xfffff78000001000ull;
	}
	else
	{
		m_KSharedUserDataBase = 0x7FFE0000;
		m_KSharedUserDataEnd = 0x7FFF0000;
	}

	uc_mem_map(m_uc, m_KSharedUserDataBase, PAGE_SIZE, UC_PROT_READ);
	uc_mem_write(m_uc, m_KSharedUserDataBase, (void *)0x7FFE0000, PAGE_SIZE);
}

ULONG64 PeEmulation::StackAlloc(ULONG AllocBytes)
{
	uint64_t rsp;
	uc_reg_read(m_uc, UC_X86_REG_RSP, &rsp);
	rsp -= AllocBytes;
	uc_reg_write(m_uc, UC_X86_REG_RSP, &rsp);
	return rsp;
}

VOID PeEmulation::StackFree(ULONG AllocBytes)
{
	uint64_t rsp;
	uc_reg_read(m_uc, UC_X86_REG_RSP, &rsp);
	rsp += AllocBytes;
	uc_reg_write(m_uc, UC_X86_REG_RSP, &rsp);
}

ULONG64 PeEmulation::HeapAlloc(ULONG AllocBytes, bool IsPageAlign)
{
	ULONG64 alloc = 0;

	for (size_t i = 0; i < m_HeapAllocs.size(); ++i)
	{
		if (m_HeapAllocs[i].free && m_HeapAllocs[i].size >= AllocBytes)
		{
			m_LastHeapAllocBytes = AllocBytes;
			m_HeapAllocs[i].free = false;
			alloc = m_HeapAllocs[i].base;
			break;
		}
	}

	if (!alloc)
	{
		for (size_t i = 0; i < m_HeapAllocs.size(); ++i)
		{
			if (alloc < m_HeapAllocs[i].base + m_HeapAllocs[i].size)
				alloc = m_HeapAllocs[i].base + m_HeapAllocs[i].size;
		}

		if (!alloc)
			alloc = m_HeapBase;

		if (IsPageAlign) 
		{
			alloc = (alloc % 0x1000ull == 0) ? alloc : AlignSize(alloc, 0x1000ull);
			AllocBytes = (AllocBytes % 0x1000 == 0) ? AllocBytes : (ULONG)AlignSize(AllocBytes, 0x1000);
		}

		if (alloc + AllocBytes > m_HeapEnd)
		{
			m_LastHeapAllocBytes = 0;
			return 0;
		}

		m_LastHeapAllocBytes = AllocBytes;
		m_HeapAllocs.emplace_back(alloc, AllocBytes);
	}

	return alloc;
}

bool PeEmulation::HeapFree(ULONG64 FreeAddress)
{
	ULONG64 maxaddr = 0;

	for (size_t i = 0; i < m_HeapAllocs.size(); ++i)
	{
		if(maxaddr < m_HeapAllocs[i].base)
			maxaddr = m_HeapAllocs[i].base;
	}

	for (size_t i = 0; i < m_HeapAllocs.size(); ++i)
	{
		if (!m_HeapAllocs[i].free && m_HeapAllocs[i].base == FreeAddress)
		{
			if (maxaddr == FreeAddress)
				m_HeapAllocs.erase(m_HeapAllocs.begin() + i);
			else
				m_HeapAllocs[i].free = true;
			return true;
		}
	}
	return false;
}

bool PeEmulation::CreateMemMapping(ULONG64 BaseAddress, ULONG64 MapAddress, ULONG Bytes)
{
	Bytes = AlignSize(Bytes, 0x1000ull);

	virtual_buffer_t buf(Bytes);
	uc_mem_read(m_uc, BaseAddress, buf.GetBuffer(), Bytes);
	uc_mem_write(m_uc, MapAddress, buf.GetBuffer(), Bytes);

	m_MemMappings.emplace_back(BaseAddress, MapAddress, Bytes);

	return true;
}

void PeEmulation::DeleteMemMapping(ULONG64 MapAddress)
{
	for (auto itor = m_MemMappings.begin(); itor != m_MemMappings.end();)
	{
		if (itor->mappedva == MapAddress)
		{
			itor = m_MemMappings.erase(itor);
			return;
		}
		else
		{
			itor++;
		}
	}
}

bool PeEmulation::WriteMemMapping(ULONG64 baseaddress, ULONG64 value, ULONG size)
{
	for (size_t i = 0; i < m_MemMappings.size(); ++i)
	{
		if (baseaddress >= m_MemMappings[i].mappedva && baseaddress < m_MemMappings[i].mappedva + m_MemMappings[i].size)
		{
			auto mapaddress = m_MemMappings[i].baseva + (baseaddress - m_MemMappings[i].mappedva);
			m_MemMappings[i].blocks.emplace_back(mapaddress, value, size);
			return true;
		}
	}
	return false;
}

void PeEmulation::FlushMemMapping(void)
{
	for (size_t i = 0; i < m_MemMappings.size(); ++i)
	{
		for (size_t j = 0; j < m_MemMappings[i].blocks.size(); ++j)
		{
			uc_mem_write(m_uc, m_MemMappings[i].blocks[j].va, &m_MemMappings[i].blocks[j].value, m_MemMappings[i].blocks[j].size);
		}
		m_MemMappings[i].blocks.clear();
	}
}

int main(int argc, char **argv)
{
	using namespace blackbone;

	PeEmulation ctx;

	if (argc < 2)
	{
		printf("usage: unicorn_pe (filename) [-k] [-disasm]\n");
		return 0;
	}

	outs = &std::cout;

	std::string filename = argv[1];
	std::wstring wfilename;
	ANSIToUnicode(filename, wfilename);

	bool bKernel = true;
	for (int i = 2; i < argc; ++i)
	{
		if (!strcmp(argv[i], "-k"))
		{
			ctx.m_IsKernel = true;
		}
		if (!strcmp(argv[i], "-disasm"))
		{
			ctx.m_DisplayDisasm = true;
		}
		if (!strcmp(argv[i], "-packed"))
		{
			ctx.m_IsPacked = true;
		}
		if (!strcmp(argv[i], "-boundcheck"))
		{
			ctx.m_BoundCheck = true;
		}
		if (!strcmp(argv[i], "-dump"))
		{
			ctx.m_Dump = true;
		}
	}

	uc_engine *uc = NULL;
	auto err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
	if (err)
	{
		printf("failed to uc_open %d\n", err);
		return 0;
	}

	auto err2 = cs_open(CS_ARCH_X86, ctx.m_IsWin64 ? CS_MODE_64 : CS_MODE_32, &ctx.m_cs);
	if (err2)
	{
		printf("failed to cs_open %d\n", err2);
		return 0;
	}

	ctx.m_uc = uc;
	ctx.thisProc.Attach(GetCurrentProcessId());

	uc_hook trace, trace2, trace3;

	uint64_t stack = (!ctx.m_IsKernel) ? 0x40000 : 0xFFFFFC0000000000ull;
	size_t stack_size = 0x10000;

	virtual_buffer_t stack_buf;
	if (!stack_buf.GetSpace(stack_size))
	{
		printf("failed to allocate virtual stack\n");
		return 0;
	}

	//allocate virtual stack for execution
	memset(stack_buf.GetBuffer(), 0, stack_buf.GetLength());
	uc_mem_map(uc, stack, stack_size, UC_PROT_READ | UC_PROT_WRITE);
	uc_mem_write(uc, stack, stack_buf.GetBuffer(), stack_size);

	ctx.m_StackBase = stack;
	ctx.m_StackEnd = stack + stack_size;
	ctx.m_LoadModuleBase = (!ctx.m_IsKernel) ? 0x180000000ull : 0xFFFFF80000000000ull;
	ctx.m_HeapBase = (!ctx.m_IsKernel) ? 0x10000000ull : 0xFFFFFA0000000000ull;
	ctx.m_HeapEnd = ctx.m_HeapBase + 0x1000000ull;

	uc_mem_map(uc, ctx.m_HeapBase, ctx.m_HeapEnd - ctx.m_HeapBase, (ctx.m_IsKernel) ? UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC : UC_PROT_READ | UC_PROT_WRITE);

	auto MapResult = ctx.thisProc.mmap().MapImage(wfilename,
		ManualImports | NoSxS | NoExceptions | NoDelayLoad | NoTLS | NoExec,
		ManualMapCallback, &ctx, nullptr, 0);

	if (!MapResult.success())
	{
		printf("failed to MapImage\n");
		return 0;
	}

	ctx.m_ImageBase = MapResult.result()->baseAddress;
	ctx.m_ImageEnd = MapResult.result()->baseAddress + MapResult.result()->size;
	ctx.m_ImageEntry = MapResult.result()->entryPoint;
	ctx.m_LastRipModule = ctx.m_ImageBase;
	ctx.m_ExecuteFromRip = ctx.m_ImageEntry;

	if (!ctx.m_IsKernel)
	{
		ctx.RegisterAPIEmulation(L"kernel32.dll", "GetSystemTimeAsFileTime", EmuGetSystemTimeAsFileTime, 1);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "GetCurrentThreadId", EmuGetCurrentThreadId, 0);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "GetCurrentProcessId", EmuGetCurrentProcessId, 0);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "QueryPerformanceCounter", EmuQueryPerformanceCounter, 1);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "LoadLibraryExW", EmuLoadLibraryExW, 3);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "LoadLibraryA", EmuLoadLibraryA, 1);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "GetProcAddress", EmuGetProcAddress, 2);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "GetModuleHandleA", EmuGetModuleHandleA, 1);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "GetLastError", EmuGetLastError, 0);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "InitializeCriticalSectionAndSpinCount", EmuInitializeCriticalSectionAndSpinCount, 2);

		if (!ctx.RegisterAPIEmulation(L"kernelbase.dll", "InitializeCriticalSectionEx", EmuInitializeCriticalSectionEx, 3))
			ctx.RegisterAPIEmulation(L"kernel32.dll", "InitializeCriticalSectionEx", EmuInitializeCriticalSectionEx, 3);

		ctx.RegisterAPIEmulation(L"ntdll.dll", "RtlDeleteCriticalSection", EmuDeleteCriticalSection, 1);
		ctx.RegisterAPIEmulation(L"ntdll.dll", "RtlIsProcessorFeaturePresent", EmuRtlIsProcessorFeaturePresent, 1);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "GetProcessAffinityMask", EmuGetProcessAffinityMask, 1);

		ctx.RegisterAPIEmulation(L"kernel32.dll", "TlsAlloc", EmuTlsAlloc, 0);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "TlsSetValue", EmuTlsSetValue, 2);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "TlsFree", EmuTlsFree, 1);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "LocalAlloc", EmuLocalAlloc, 2);
		ctx.RegisterAPIEmulation(L"ntdll.dll", "NtProtectVirtualMemory", EmuNtProtectVirtualMemory, 5);
	}
	else
	{
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "ExAllocatePool", EmuExAllocatePool, 2);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "ExAllocatePoolWithTag", EmuExAllocatePool, 3);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "NtQuerySystemInformation", EmuNtQuerySystemInformation, 4);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "ZwQuerySystemInformation", EmuNtQuerySystemInformation, 4);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "ExFreePool", EmuExFreePool, 1);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "ExFreePoolWithTag", EmuExFreePoolWithTag, 2);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "IoAllocateMdl", EmuIoAllocateMdl, 5);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "MmProbeAndLockPages", EmuMmProbeAndLockPages, 3); 
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "MmMapLockedPagesSpecifyCache", EmuMmMapLockedPagesSpecifyCache, 6);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "KeQueryActiveProcessors", EmuKeQueryActiveProcessors, 0);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "KeSetSystemAffinityThread", EmuKeSetSystemAffinityThread, 1);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "KeRevertToUserAffinityThread", EmuKeRevertToUserAffinityThread, 0);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "MmUnlockPages", EmuMmUnlockPages, 1);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "IoFreeMdl", EmuIoFreeMdl, 1);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "RtlGetVersion", EmuRtlGetVersion, 1);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "DbgPrint", EmuDbgPrint, 1);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "KeInitializeMutex", EmuKeInitializeMutex, 2);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "RtlInitUnicodeString", EmuRtlInitUnicodeString, 2);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "KeWaitForSingleObject", EmuKeWaitForSingleObject, 5);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "KeWaitForMutexObject", EmuKeWaitForSingleObject, 5);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "KeReleaseMutex", EmuKeReleaseMutex, 2);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "srand", Emusrand, 1);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "rand", Emurand, 0);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "RtlZeroMemory", EmuRtlZeroMemory, 2);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "RtlCopyMemory", EmuRtlCopyMemory, 3);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "RtlFillMemory", EmuRtlFillMemory, 3);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "wcsstr", Emuwcsstr, 2);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "MmIsAddressValid", EmuMmIsAddressValid, 1);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "ExGetPreviousMode", EmuExGetPreviousMode, 1);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "__C_specific_handler", Emu__C_specific_handler, 4);
	}

	memset(&ctx.m_InitReg, 0, sizeof(ctx.m_InitReg));
	ctx.m_InitReg.Rsp = ctx.m_StackEnd - 64;

	ctx.InitProcessorState();

	if (!ctx.m_IsKernel)
	{
		ctx.InitTebPeb();

		ctx.m_InitReg.Rcx = ctx.m_ImageBase;
		ctx.m_InitReg.Rdx = DLL_PROCESS_ATTACH;
		ctx.m_InitReg.R8 = 0;
	}
	else
	{
		ctx.SortModuleList();
		ctx.InitPsLoadedModuleList();
		ctx.InitDriverObject();

		ctx.m_InitReg.Rcx = ctx.m_DriverObjectBase;
		ctx.m_InitReg.Rdx = 0;
	}
	
	ctx.InitKSharedUserData();	

	//return to image end when entrypoint is executed
	uc_mem_write(uc, ctx.m_InitReg.Rsp, &ctx.m_ImageEnd, sizeof(ctx.m_ImageEnd));
	uc_mem_map(uc, ctx.m_ImageEnd, 0x1000, UC_PROT_EXEC | UC_PROT_READ);

	uc_reg_write(uc, UC_X86_REG_RAX, &ctx.m_InitReg.Rax);
	uc_reg_write(uc, UC_X86_REG_RBX, &ctx.m_InitReg.Rbx);
	uc_reg_write(uc, UC_X86_REG_RCX, &ctx.m_InitReg.Rcx);
	uc_reg_write(uc, UC_X86_REG_RDX, &ctx.m_InitReg.Rdx);
	uc_reg_write(uc, UC_X86_REG_RSI, &ctx.m_InitReg.Rsi);
	uc_reg_write(uc, UC_X86_REG_RDI, &ctx.m_InitReg.Rdi);
	uc_reg_write(uc, UC_X86_REG_R8, &ctx.m_InitReg.R8);
	uc_reg_write(uc, UC_X86_REG_R9, &ctx.m_InitReg.R9);
	uc_reg_write(uc, UC_X86_REG_R10, &ctx.m_InitReg.R10);
	uc_reg_write(uc, UC_X86_REG_R11, &ctx.m_InitReg.R11);
	uc_reg_write(uc, UC_X86_REG_R12, &ctx.m_InitReg.R12);
	uc_reg_write(uc, UC_X86_REG_R13, &ctx.m_InitReg.R13);
	uc_reg_write(uc, UC_X86_REG_R14, &ctx.m_InitReg.R14);
	uc_reg_write(uc, UC_X86_REG_R15, &ctx.m_InitReg.R15);
	uc_reg_write(uc, UC_X86_REG_RBP, &ctx.m_InitReg.Rbp);
	uc_reg_write(uc, UC_X86_REG_RSP, &ctx.m_InitReg.Rsp);

	uc_hook_add(uc, &trace, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | 
		UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT | UC_HOOK_MEM_WRITE_PROT,
		InvalidRwxCallback, &ctx, 1, 0);

	uc_hook_add(uc, &trace2, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH,
		RwxCallback, &ctx, 1, 0);

	uc_hook_add(uc, &trace3, UC_HOOK_CODE,
		CodeCallback, &ctx, 1, 0);

	uc_hook_add(uc, &trace3, UC_HOOK_INTR,
		IntrCallback, &ctx, 1, 0);

	while (1)
	{
		err = uc_emu_start(uc, ctx.m_ExecuteFromRip, ctx.m_ImageEnd, 0, 0);

		if (ctx.m_LastException != STATUS_SUCCESS)
		{
			auto except = ctx.m_LastException;
			ctx.m_LastException = STATUS_SUCCESS;
			ctx.RtlRaiseStatus(except);
		}
		else
		{
			break;
		}
	}

	uc_hook_del(uc, trace);
	uc_hook_del(uc, trace2);
	uc_hook_del(uc, trace3);

	uint64_t result_rax = 0;
	uc_reg_read(uc, UC_X86_REG_RAX, &result_rax);

	if(ctx.m_Dump)
	{
		virtual_buffer_t imagebuf(ctx.m_ImageEnd - ctx.m_ImageBase);
		virtual_buffer_t RebuildSectionBuffer;

		uc_mem_read(uc, ctx.m_ImageBase, imagebuf.GetBuffer(), ctx.m_ImageEnd - ctx.m_ImageBase);

		auto ntheader = RtlImageNtHeader(imagebuf.GetBuffer());

		auto SectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)ntheader + sizeof(ntheader->Signature) + \
			sizeof(ntheader->FileHeader) + ntheader->FileHeader.SizeOfOptionalHeader);

		auto SectionCount = ntheader->FileHeader.NumberOfSections;
		for (USHORT i = 0; i < SectionCount; ++i)
		{
			SectionHeader[i].PointerToRawData = SectionHeader[i].VirtualAddress;
			SectionHeader[i].SizeOfRawData = SectionHeader[i].Misc.VirtualSize;
		}

		//ctx.RebuildSection(imagebuf.GetBuffer(), (ULONG)(ctx.m_ImageEnd - ctx.m_ImageBase), RebuildSectionBuffer);

		if (ctx.m_ImageRealEntry)
			ntheader->OptionalHeader.AddressOfEntryPoint = (ULONG)(ctx.m_ImageRealEntry - ctx.m_ImageBase);

		auto dumpfile = filename + ".dump";

		FILE *fp = fopen(dumpfile.c_str(), "wb");

		fwrite(imagebuf.GetBuffer(), ctx.m_ImageEnd - ctx.m_ImageBase, 1, fp);
	
		if(RebuildSectionBuffer.GetBuffer())
			fwrite(RebuildSectionBuffer.GetBuffer(), RebuildSectionBuffer.GetLength(), 1, fp);

		fclose(fp);
	}

	uc_close(uc);

	cs_close(&ctx.m_cs);

	ctx.thisProc.mmap().UnmapAllModules();

	*outs << "uc_emu_start return: " << std::dec << err << "\n";

	*outs << "entrypoint return: " << std::hex << result_rax << "\n";
	*outs << "last rip: " << std::hex << ctx.m_LastRip;
	
	std::stringstream rip_region, realentry_region;
	if(ctx.FindAddressInRegion(ctx.m_LastRip, rip_region))
		*outs << " (" << rip_region.str() << ")\n";

	if (ctx.m_ImageRealEntry)
	{
		if (ctx.FindAddressInRegion(ctx.m_ImageRealEntry, realentry_region))
			*outs << "real entrypoint: " << realentry_region.str() << "\n";
	}

	outs->flush();

	return 0;
}