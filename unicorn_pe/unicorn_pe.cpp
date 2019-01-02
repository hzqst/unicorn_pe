#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <BlackBone/Process/Process.h>
#include <BlackBone/ManualMap/MMap.h>

#include <iostream>
#include <sstream>
#include <functional>
#include <vector>
#include <intrin.h>

#include "buffer.h"
#include "encode.h"
#include "nativestructs.h"

#pragma comment(lib,"ntdll.lib")

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

using api_emu_callback = std::function<bool(uc_engine *uc)>;

typedef struct FakeAPI_s
{
	FakeAPI_s(const char *n, uint64_t va) : ProcedureName(n), VirtualAddress(va) {
		EmuCallback = NULL;
	}
	std::string ProcedureName;
	void *EmuCallback;
	uint64_t VirtualAddress;
}FakeAPI_t;

typedef struct FakeModule_s
{
	FakeModule_s(ULONG64 b, ULONG s, const std::wstring &n) : ImageBase(b), ImageSize(s), DllName(n) {

	}
	ULONG64 ImageBase;
	ULONG ImageSize;
	std::wstring DllName;
	std::vector<FakeAPI_t> FakeAPIs;
}FakeModule_t;

typedef struct AllocBlock_s
{
	AllocBlock_s(uint64_t b, ULONG s) : base(b), size(s) {
		free = false;
	}
	ULONG64 base;
	ULONG size;
	bool free;
}AllocBlock_t;

class PeEmulation
{
public:
	PeEmulation()
	{
		m_IsKernel = false;
		m_IsWin64 = true;
		m_TlsValue = -1;
		m_PebBase = 0;
		m_PebEnd = 0;
		m_TebBase = 0;
		m_TebEnd = 0;
		m_DriverObjectBase = 0;
	}

	void InitProcessorState();
	void InitTebPeb();
	void InitDriverObject();
	void InitKSharedUserData();

	void MapImageToEngine(const std::wstring &ImageName, PVOID ImageBase, ULONG ImageSize, ULONG64 MappedBase);
	bool FindAddressInRegion(ULONG64 address, std::stringstream &RegionName);
	bool FindAPIByAddress(ULONG64 address, std::wstring &DllName, FakeAPI_t **api);
	bool FindModuleByAddress(ULONG64 address, ULONG64 &DllBase);
	bool RegisterAPIEmulation(const std::wstring &DllName, const char *ProcedureName, void *callback, int argsCount);
	void AddAPIEmulation(FakeAPI_t *r, void *callback, int argsCount);
	
	VOID LdrResolveExportTable(FakeModule_t *module, PVOID ImageBase, ULONG64 MappedBase);
	ULONG64 LdrGetProcAddress(ULONG64 ImageBase, const char *ProcedureName);
	NTSTATUS LdrFindDllByName(const std::wstring &DllName, ULONG64 *ImageBase, ULONG *ImageSize, bool LoadIfNotExist);
	NTSTATUS LdrLoadDllByName(const std::wstring &DllName, ULONG64 *ImageBase, ULONG *ImageSize);

	ULONG64 HeapAlloc(ULONG Bytes);
	bool HeapFree(ULONG64 FreeAddress);
public:
	csh m_cs;
	uc_engine *m_uc;
	bool m_IsWin64;
	bool m_IsKernel;
	uint64_t m_KSharedUserDataBase;
	uint64_t m_KSharedUserDataEnd;
	uint64_t m_StackBase;
	uint64_t m_StackEnd;
	uint64_t m_ImageBase;
	uint64_t m_ImageEnd;
	uint64_t m_ImageEntry;
	uint64_t m_HeapBase;
	uint64_t m_HeapEnd;
	uint64_t m_LoadModuleBase;

	//usermode only
	uint64_t m_PebBase;
	uint64_t m_PebEnd;
	uint64_t m_TebBase;
	uint64_t m_TebEnd;

	//kernelmode only
	uint64_t m_DriverObjectBase;

	std::vector<FakeModule_t *> m_FakeModules;
	std::vector<AllocBlock_t> m_HeapAllocs;
	uint64_t m_TlsValue;
	uint64_t m_LastRipModule;
	blackbone::Process thisProc;
};

#define API_FUNCTION_SIZE 8
#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(Va) (ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)
#define PAGE_ALIGN_64(Va) (Va) & ~(0x1000ull - 1)
#define PAGE_ALIGN_64k(Va) ((Va)) & ~(0x10000ull - 1)

#define AlignSize(Size, Align) (Size+Align-1)/Align*Align

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
		ctx->MapImageToEngine(modInfo.name, (PVOID)modInfo.imgPtr, modInfo.size, modInfo.baseAddress);
	}

	return blackbone::LoadData(blackbone::MT_Default, blackbone::Ldr_None, 0);
};

void PeEmulation::AddAPIEmulation(FakeAPI_t *r, void *callback, int argsCount)
{
	r->EmuCallback = callback;

	if (callback)
	{
		uc_err err;

		if (argsCount > 4)
		{
			unsigned char code[] = "\x48\x83\xC4\x00\xC3";

			code[3] = argsCount * 8;

			err = uc_mem_write(m_uc, r->VirtualAddress, code, sizeof(code));
		}
		else
		{
			unsigned char code[] = "\xC3";

			err = uc_mem_write(m_uc, r->VirtualAddress, code, sizeof(code));
		}

		uc_hook trace;
		err = uc_hook_add(m_uc, &trace, UC_HOOK_CODE, callback, this, r->VirtualAddress, r->VirtualAddress + API_FUNCTION_SIZE - 1);
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
			printf("failed to register API emulation for %s\n", ProcedureName);
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

bool PeEmulation::FindModuleByAddress(ULONG64 address, ULONG64 &DllBase)
{
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

	auto moduleptr = thisProc.modules().GetModule(DllName, ManualOnly, mt_default);

	if (moduleptr)
	{
		if (ImageBase)
			*ImageBase = moduleptr->baseAddress;
		if (ImageSize)
			*ImageSize = moduleptr->size;

		return STATUS_SUCCESS;
	}

	if(LoadIfNotExist)
		return LdrLoadDllByName(DllName, ImageBase, ImageSize);

	return STATUS_OBJECT_NAME_NOT_FOUND;
}

NTSTATUS PeEmulation::LdrLoadDllByName(const std::wstring &DllName, ULONG64 *ImageBase, ULONG *ImageSize)
{
	using namespace blackbone;

	auto MapResult = thisProc.mmap().MapImage(DllName,
		ManualImports | NoSxS | NoExceptions | NoDelayLoad | NoTLS | NoExec,
		ManualMapCallback, this);

	if (!MapResult.success())
	{
		printf("failed to MapImage %ws\n", DllName.c_str());
		return MapResult.status;
	}

	return STATUS_SUCCESS;
}

static void EmuUnknownAPI(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

void PeEmulation::MapImageToEngine(const std::wstring &ImageName, PVOID ImageBase, ULONG ImageSize, ULONG64 MappedBase)
{
	FakeModule_t *mod = new FakeModule_t(MappedBase, ImageSize, ImageName);
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
			uc_hook trace3;
			uc_hook_add(m_uc, &trace3, UC_HOOK_CODE, EmuUnknownAPI,
				this, image_base + SectionHeader[i].VirtualAddress,
				image_base + SectionHeader[i].VirtualAddress + SectionSize - 1);
		}
	}
}

bool EmuReadNullTermString(uc_engine *uc, uint64_t address, std::string &str)
{
	char c;
	uc_err err;
	size_t len = 0;
	while (1)
	{
		err = uc_mem_read(uc, address + len, &c, sizeof(char));
		if (err != UC_ERR_OK)
			return false;
		if (c != '\0')
			str.push_back(c);
		else
			break;

		len += sizeof(char);

		if (len > 1024 * sizeof(char))
			break;
	}

	return true;
}

bool EmuReadNullTermUnicodeString(uc_engine *uc, uint64_t address, std::wstring &str)
{
	wchar_t c;
	uc_err err;
	size_t len = 0;
	while (1)
	{
		err = uc_mem_read(uc, address + len, &c, sizeof(wchar_t));
		if (err != UC_ERR_OK)
			return false;
		if (c != L'\0')
			str.push_back(c);
		else
			break;

		len += sizeof(wchar_t);

		if (len > 1024 * sizeof(wchar_t))
			break;
	}

	return true;
}

uint64_t EmuReadReturnAddress(uc_engine *uc)
{
	uint64_t rsp;
	uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
	uc_mem_read(uc, rsp, &rsp, 8);

	return rsp;
}

static void CodeDisasmCallback(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;
	
	unsigned char codeBuffer[15];
	uc_mem_read(uc, address, codeBuffer, size);

	cs_insn insn;
	memset(&insn, 0, sizeof(insn));

	uint64_t virtualBase = address;
	uint8_t *code = codeBuffer;
	size_t codeSize = size;
	cs_disasm_iter(ctx->m_cs, (const uint8_t **)&code, &codeSize, &virtualBase, &insn);

	printf("%016I64X\t\t\t%s\t\t%s\n", address, insn.mnemonic, insn.op_str);
}

static bool InvalidRwxCallback(uc_engine *uc, uc_mem_type type,
	uint64_t address, int size, int64_t value, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	switch (type) {
	case UC_MEM_FETCH_PROT: {
		auto retaddr = EmuReadReturnAddress(uc);
		std::stringstream region;
		if (ctx->FindAddressInRegion(retaddr, region))
			std::cout << "UC_MEM_FETCH_PROT API called from" << region.str() << "\n";
		uc_emu_stop(uc);
		break;
	}
	case UC_MEM_FETCH_UNMAPPED: {
		auto retaddr = EmuReadReturnAddress(uc);
		std::stringstream region;
		if (ctx->FindAddressInRegion(retaddr, region))
			std::cout << "UC_MEM_FETCH_UNMAPPED API called from" << region.str() << "\n";
		uc_emu_stop(uc);
		break;
	}
	case UC_MEM_READ_UNMAPPED: {
		uint64_t rip;
		uc_reg_read(uc, UC_X86_REG_RIP, &rip);
		std::stringstream region;
		if (ctx->FindAddressInRegion(rip, region))
			std::cout << "UC_MEM_READ_UNMAPPED rip at " << region.str() << "\n";

		uc_emu_stop(uc);
		break;
	}
	case UC_MEM_WRITE_UNMAPPED: {
		uint64_t rip;
		uc_reg_read(uc, UC_X86_REG_RIP, &rip);
		std::stringstream region;
		if (ctx->FindAddressInRegion(rip, region))
			std::cout << "UC_MEM_WRITE_UNMAPPED rip at " << region.str() << "\n";
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
		std::stringstream region;
		if (!ctx->FindAddressInRegion(address, region))
		{
			printf("UC_MEM_READ out of region\n");

			uint64_t rip;
			uc_reg_read(uc, UC_X86_REG_RIP, &rip);
			if (ctx->FindAddressInRegion(rip, region))
				std::cout << "UC_MEM_READ rip at " << region.str() << "\n";

			uc_emu_stop(uc);
		}

		break;
	}
	case UC_MEM_WRITE: {
		std::stringstream region;
		if (!ctx->FindAddressInRegion(address, region))
		{
			printf("UC_MEM_WRITE out of region\n");

			uint64_t rip;
			uc_reg_read(uc, UC_X86_REG_RIP, &rip);
			if (ctx->FindAddressInRegion(rip, region))
				std::cout << "UC_MEM_WRITE rip at " << region.str() << "\n";

			uc_emu_stop(uc);
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
					printf("API emulation callback not registered %ws!%s\n", DllName.c_str(), api->ProcedureName.c_str());
					auto retaddr = EmuReadReturnAddress(uc);
					if (retaddr >= ctx->m_ImageBase && retaddr < ctx->m_ImageEnd)
						printf("called from imagebase+0x%X\n", (ULONG)(retaddr - ctx->m_ImageBase));
					uc_emu_stop(uc);
				}
			}
			else
			{
				printf("unknown API called\n");
				auto retaddr = EmuReadReturnAddress(uc);
				if (retaddr >= ctx->m_ImageBase && retaddr < ctx->m_ImageEnd)
					printf("called from imagebase+0x%X\n", (ULONG)(retaddr - ctx->m_ImageBase));
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
}

static void EmuGetSystemTimeAsFileTime(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);

	err = uc_mem_write(uc, rcx, &ft, sizeof(FILETIME));
}

static void EmuGetCurrentThreadId(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	DWORD ThreadId = 1024;

	auto err = uc_reg_write(uc, UC_X86_REG_EAX, &ThreadId);
}

static void EmuGetCurrentProcessId(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	DWORD ProcessId = 1000;

	auto err = uc_reg_write(uc, UC_X86_REG_EAX, &ProcessId);
}

static void EmuQueryPerformanceCounter(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	LARGE_INTEGER li;
	BOOL r = QueryPerformanceCounter(&li);

	err = uc_mem_write(uc, rcx, &li, sizeof(LARGE_INTEGER));

	err = uc_reg_write(uc, UC_X86_REG_EAX, &r);
}

static void EmuLoadLibraryExW(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint64_t rdx;
	err = uc_reg_read(uc, UC_X86_REG_RDX, &rdx);

	uint32_t r8d;
	err = uc_reg_read(uc, UC_X86_REG_R8D, &r8d);

	std::wstring DllName;
	uint64_t r = 0;
	if (EmuReadNullTermUnicodeString(uc, rcx, DllName))
	{
		printf("EmuLoadLibraryExW %ws\n", DllName.c_str());

		ULONG64 ImageBase = 0;
		NTSTATUS st = ctx->LdrFindDllByName(DllName, &ImageBase, NULL, true);
		if (NT_SUCCESS(st))
		{
			r = ImageBase;
		}
	}

	err = uc_reg_write(uc, UC_X86_REG_RAX, &r);
}

static void EmuGetProcAddress(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint64_t rdx;
	err = uc_reg_read(uc, UC_X86_REG_RDX, &rdx);

	std::string ProcedureName;
	uint64_t r = 0;
	if (EmuReadNullTermString(uc, rdx, ProcedureName))
	{
		printf("GetProcAddress %s\n", ProcedureName.c_str());

		r = ctx->LdrGetProcAddress(rcx, ProcedureName.c_str());
	}

	err = uc_reg_write(uc, UC_X86_REG_RAX, &r);
}

static void EmuGetModuleHandleA(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	std::string ModuleName;
	uint64_t r = 0;
	if (EmuReadNullTermString(uc, rcx, ModuleName))
	{
		printf("GetModuleHandleA %s\n", ModuleName.c_str());

		std::wstring wModuleName;
		ANSIToUnicode(ModuleName, wModuleName);
		ctx->LdrFindDllByName(wModuleName, &r, NULL, false);
	}

	err = uc_reg_write(uc, UC_X86_REG_RAX, &r);
}

static void EmuGetLastError(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint32_t r = 0;

	auto err = uc_reg_write(uc, UC_X86_REG_EAX, &r);
}

typedef struct _RTL_CRITICAL_SECTION_64 {
	uint64_t DebugInfo;
	uint32_t LockCount;
	uint32_t RecursionCount;
	uint64_t OwningThread;
	uint64_t LockSemaphore;
	uint64_t SpinCount;
} RTL_CRITICAL_SECTION_64, *PRTL_CRITICAL_SECTION_64;

static void EmuInitializeCriticalSectionAndSpinCount(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint32_t edx;
	err = uc_reg_read(uc, UC_X86_REG_EDX, &edx);

	RTL_CRITICAL_SECTION_64 CrtSection;
	CrtSection.DebugInfo = 0;
	CrtSection.LockCount = 0;
	CrtSection.LockSemaphore = 0;
	CrtSection.OwningThread = 0;
	CrtSection.RecursionCount = 0;
	CrtSection.SpinCount = edx;

	uc_mem_write(uc, rcx, &CrtSection, sizeof(RTL_CRITICAL_SECTION_64));

	uint32_t r = 1;

	err = uc_reg_write(uc, UC_X86_REG_EAX, &r);
}

static void EmuInitializeCriticalSectionEx(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint32_t edx;
	err = uc_reg_read(uc, UC_X86_REG_EDX, &edx);

	uint32_t r8d;
	err = uc_reg_read(uc, UC_X86_REG_R8D, &r8d);

	RTL_CRITICAL_SECTION_64 CrtSection;
	CrtSection.DebugInfo = 0;
	CrtSection.LockCount = 0;
	CrtSection.LockSemaphore = 0;
	CrtSection.OwningThread = 0;
	CrtSection.RecursionCount = 0;
	CrtSection.SpinCount = edx;

	uc_mem_write(uc, rcx, &CrtSection, sizeof(RTL_CRITICAL_SECTION_64));

	uint32_t r = 1;

	err = uc_reg_write(uc, UC_X86_REG_EAX, &r);
}

static void EmuTlsAlloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint32_t r = 0;

	auto err = uc_reg_write(uc, UC_X86_REG_EAX, &r);
}

static void EmuTlsSetValue(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint32_t r = 0;

	uint64_t ecx;
	auto err = uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

	if (ecx == 0)
	{
		uint64_t rdx;
		err = uc_reg_read(uc, UC_X86_REG_RDX, &rdx);

		r = 1;

		//ctx->m_TlsValue = rdx;
	}

	err = uc_reg_write(uc, UC_X86_REG_EAX, &r);
}

static void EmuTlsFree(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint32_t r = 0;

	uint64_t ecx;
	auto err = uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

	if (ecx == 0)
	{
		r = 1;
	}

	err = uc_reg_write(uc, UC_X86_REG_EAX, &r);
}

static void EmuDeleteCriticalSection(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	RTL_CRITICAL_SECTION_64 CrtSection;
	CrtSection.DebugInfo = 0;
	CrtSection.LockCount = 0;
	CrtSection.LockSemaphore = 0;
	CrtSection.OwningThread = 0;
	CrtSection.RecursionCount = 0;
	CrtSection.SpinCount = 0;

	uc_mem_write(uc, rcx, &CrtSection, sizeof(RTL_CRITICAL_SECTION_64));
}

static void EmuLocalAlloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t alloc = 0;

	uint32_t ecx;
	auto err = uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

	uint32_t edx;
	err = uc_reg_read(uc, UC_X86_REG_EDX, &edx);

	if (ecx == LMEM_FIXED)
	{
		alloc = ctx->HeapAlloc(edx);
	}

	printf("LocalAlloc %d bytes, allocated at 0x%I64x\n", edx, alloc);

	err = uc_reg_write(uc, UC_X86_REG_RAX, &alloc);
}

static void EmuRtlIsProcessorFeaturePresent(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint8_t al = 0;

	uint32_t ecx;
	auto err = uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

	if (ecx == 0x1C)
	{
		al = 0;
	}
	else
	{
		al = IsProcessorFeaturePresent(ecx);
	}

	printf("RtlIsProcessorFeaturePresent feature %d\n", ecx);

	err = uc_reg_write(uc, UC_X86_REG_AL, &al);
}

static void EmuExAllocatePool(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t alloc = 0;

	uint32_t ecx;
	auto err = uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

	uint32_t edx;
	err = uc_reg_read(uc, UC_X86_REG_EDX, &edx);

	alloc = ctx->HeapAlloc(edx);

	printf("ExAllocatePool type %d, %d bytes, allocated at 0x%I64x\n", ecx, edx, alloc);

	err = uc_reg_write(uc, UC_X86_REG_RAX, &alloc);
}

static void EmuNtQuerySystemInformation(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint32_t ecx;
	auto err = uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

	uint64_t rdx;
	err = uc_reg_read(uc, UC_X86_REG_RDX, &rdx);

	uint32_t r8d;
	err = uc_reg_read(uc, UC_X86_REG_R8D, &r8d);

	uint64_t r9;
	err = uc_reg_read(uc, UC_X86_REG_R9, &r9);
	
	char *buf = (char *)malloc(r8d);
	memset(buf, 0, r8d);

	ULONG retlen = 0;

	uint32_t eax = (uint32_t)NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)ecx, buf, r8d, &retlen);

	if (eax == STATUS_INFO_LENGTH_MISMATCH)
	{

	}
	else if (eax == STATUS_SUCCESS)
	{
		if (ecx == (uint32_t)SystemModuleInformation)
		{
			auto pMods = (PRTL_PROCESS_MODULES)buf;
			PRTL_PROCESS_MODULES newMods = (PRTL_PROCESS_MODULES)malloc(r8d);
			memset(newMods, 0, r8d);

			ULONG numberNewMods = 0;
			for (ULONG i = 0; i < pMods->NumberOfModules; i++)
			{
				PCHAR modname = (PCHAR)pMods->Modules[i].FullPathName + pMods->Modules[i].OffsetToFileName;
				std::wstring wModName;
				ANSIToUnicode(modname, wModName);

				ULONG64 ImageBase = 0;
				ULONG ImageSize = 0;
				auto stFind = ctx->LdrFindDllByName(wModName, &ImageBase, &ImageSize, false);
				if (stFind == STATUS_SUCCESS)
				{
					memcpy(&newMods->Modules[numberNewMods], &pMods->Modules[i], sizeof(pMods->Modules[i]));
					newMods->Modules[numberNewMods].ImageBase = (PVOID)ImageBase;
					newMods->Modules[numberNewMods].ImageSize = ImageSize;
					numberNewMods++;
				}
			}
			newMods->NumberOfModules = numberNewMods;

			retlen = offsetof(RTL_PROCESS_MODULES, Modules) + sizeof(newMods->Modules[0]) * numberNewMods;

			uc_mem_write(uc, rdx, newMods, retlen);

			free(newMods);
			
		}
	}
	if (r9 != 0)
	{
		uc_mem_write(uc, r9, &retlen, sizeof(retlen));
	}

	free(buf);

	printf("NtQuerySystemInformation type %d, return %08X\n", ecx, eax);

	err = uc_reg_write(uc, UC_X86_REG_EAX, &eax);
}

static void EmuExFreePoolWithTag(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t alloc = 0;

	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint32_t edx;
	err = uc_reg_read(uc, UC_X86_REG_EDX, &edx);

	ctx->HeapFree(rcx);

	printf("ExFreePoolWithTag free 0x%I64x\n", rcx);
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
}

void PeEmulation::InitTebPeb()
{
	PEB peb = { 0 };

	m_PebBase = 0x90000ull;
	m_PebEnd = m_PebBase + PAGE_ALIGN(sizeof(PEB) + PAGE_SIZE);

	uc_mem_map(m_uc, m_PebBase, PAGE_ALIGN(sizeof(PEB)), UC_PROT_READ);
	uc_mem_write(m_uc, m_PebBase, &peb, sizeof(PEB));

	m_TebBase = 0x80000ull;
	m_TebEnd = m_TebBase + PAGE_ALIGN(sizeof(TEB) + PAGE_SIZE);

	TEB teb = { 0 };

	teb.ProcessEnvironmentBlock = (PPEB)m_PebBase;

	uc_mem_map(m_uc, m_TebBase, PAGE_ALIGN(sizeof(TEB)), UC_PROT_READ);
	uc_mem_write(m_uc, m_TebBase, &teb, sizeof(TEB));

	uc_x86_msr msr;
	msr.rid = (uint32_t)Msr::kIa32GsBase;
	msr.value = m_TebBase;

	uc_reg_write(m_uc, UC_X86_REG_MSR, &msr);
}

void PeEmulation::InitDriverObject()
{
	DRIVER_OBJECT DriverObject = { 0 };
	DriverObject.DriverSize = (ULONG)(m_ImageEnd - m_ImageBase);
	DriverObject.DriverStart = (PVOID)m_ImageEntry;
	DriverObject.Size = sizeof(DRIVER_OBJECT);

	m_DriverObjectBase = HeapAlloc(sizeof(DRIVER_OBJECT));
	uc_mem_write(m_uc, m_DriverObjectBase, &DriverObject, sizeof(DRIVER_OBJECT));
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

ULONG64 PeEmulation::HeapAlloc(ULONG AllocBytes)
{
	ULONG64 alloc = 0;

	for (size_t i = 0; i < m_HeapAllocs.size(); ++i)
	{
		if (m_HeapAllocs[i].free && m_HeapAllocs[i].size >= AllocBytes)
		{
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
		m_HeapAllocs.emplace_back(alloc, AllocBytes);
	}

	return alloc;
}

bool PeEmulation::HeapFree(ULONG64 FreeAddress)
{
	for (size_t i = 0; i < m_HeapAllocs.size(); ++i)
	{
		if (!m_HeapAllocs[i].free && m_HeapAllocs[i].base == FreeAddress)
		{
			m_HeapAllocs[i].free = true;
			return true;
		}
	}

	return false;
}

int main(int argc, char **argv)
{
	using namespace blackbone;

	PeEmulation ctx;

	if (argc < 2)
	{
		printf("usage: unicorn_pe (filename) [-k]\n");
		return 0;
	}

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
	}

	uc_engine *uc = NULL;
	auto err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
	if (err)
	{
		printf("failed to uc_open %d\n", err);
		return 0;
	}

	cs_err err2 = cs_open(CS_ARCH_X86, ctx.m_IsWin64 ? CS_MODE_64 : CS_MODE_32, &ctx.m_cs);

	ctx.m_uc = uc;
	ctx.thisProc.Attach(GetCurrentProcessId());

	uc_hook trace, trace2;

	uint64_t stack = (!ctx.m_IsKernel) ? 0x40000 : 0xFFFFFB0000000000ull;
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
	ctx.m_HeapEnd = ctx.m_HeapBase + 0x400000ull;

	uc_mem_map(uc, ctx.m_HeapBase, ctx.m_HeapEnd - ctx.m_HeapBase, UC_PROT_READ | UC_PROT_WRITE);

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

	if (!ctx.m_IsKernel)
	{
		ctx.RegisterAPIEmulation(L"kernel32.dll", "GetSystemTimeAsFileTime", EmuGetSystemTimeAsFileTime, 1);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "GetCurrentThreadId", EmuGetCurrentThreadId, 0);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "GetCurrentProcessId", EmuGetCurrentProcessId, 0);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "QueryPerformanceCounter", EmuQueryPerformanceCounter, 1);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "LoadLibraryExW", EmuLoadLibraryExW, 3);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "GetProcAddress", EmuGetProcAddress, 2);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "GetModuleHandleA", EmuGetModuleHandleA, 1);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "GetLastError", EmuGetLastError, 0);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "InitializeCriticalSectionAndSpinCount", EmuInitializeCriticalSectionAndSpinCount, 2);

		if (!ctx.RegisterAPIEmulation(L"kernelbase.dll", "InitializeCriticalSectionEx", EmuInitializeCriticalSectionEx, 3))
			ctx.RegisterAPIEmulation(L"kernel32.dll", "InitializeCriticalSectionEx", EmuInitializeCriticalSectionEx, 3);

		ctx.RegisterAPIEmulation(L"ntdll.dll", "RtlDeleteCriticalSection", EmuDeleteCriticalSection, 1);

		ctx.RegisterAPIEmulation(L"ntdll.dll", "RtlIsProcessorFeaturePresent", EmuRtlIsProcessorFeaturePresent, 1);

		ctx.RegisterAPIEmulation(L"kernel32.dll", "TlsAlloc", EmuTlsAlloc, 0);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "TlsSetValue", EmuTlsSetValue, 2);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "TlsFree", EmuTlsFree, 1);
		ctx.RegisterAPIEmulation(L"kernel32.dll", "LocalAlloc", EmuLocalAlloc, 2);
	}
	else
	{
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "ExAllocatePool", EmuExAllocatePool, 2);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "NtQuerySystemInformation", EmuNtQuerySystemInformation, 4);
		ctx.RegisterAPIEmulation(L"ntoskrnl.exe", "ExFreePoolWithTag", EmuExFreePoolWithTag, 2);
	}

	_CONTEXT reg64;
	memset(&reg64, 0, sizeof(reg64));
	reg64.Rsp = ctx.m_StackEnd - 64;

	if (!ctx.m_IsKernel)
	{
		reg64.Rcx = ctx.m_ImageBase;
		reg64.Rdx = DLL_PROCESS_ATTACH;
		reg64.R8 = 0;

		ctx.InitTebPeb();
	}
	else
	{
		ctx.InitDriverObject();
		reg64.Rcx = ctx.m_DriverObjectBase;
		reg64.Rdx = 0;
	}

	ctx.InitProcessorState();
	ctx.InitKSharedUserData();	

	//return to image end when entrypoint is executed
	uc_mem_write(uc, reg64.Rsp, &ctx.m_ImageEnd, sizeof(ctx.m_ImageEnd));
	uc_mem_map(uc, ctx.m_ImageEnd, 0x1000, UC_PROT_EXEC | UC_PROT_READ);

	uc_reg_write(uc, UC_X86_REG_RAX, &reg64.Rax);
	uc_reg_write(uc, UC_X86_REG_RBX, &reg64.Rbx);
	uc_reg_write(uc, UC_X86_REG_RCX, &reg64.Rcx);
	uc_reg_write(uc, UC_X86_REG_RDX, &reg64.Rdx);
	uc_reg_write(uc, UC_X86_REG_RSI, &reg64.Rsi);
	uc_reg_write(uc, UC_X86_REG_RDI, &reg64.Rdi);
	uc_reg_write(uc, UC_X86_REG_R8, &reg64.R8);
	uc_reg_write(uc, UC_X86_REG_R9, &reg64.R9);
	uc_reg_write(uc, UC_X86_REG_R10, &reg64.R10);
	uc_reg_write(uc, UC_X86_REG_R11, &reg64.R11);
	uc_reg_write(uc, UC_X86_REG_R12, &reg64.R12);
	uc_reg_write(uc, UC_X86_REG_R13, &reg64.R13);
	uc_reg_write(uc, UC_X86_REG_R14, &reg64.R14);
	uc_reg_write(uc, UC_X86_REG_R15, &reg64.R15);
	uc_reg_write(uc, UC_X86_REG_RBP, &reg64.Rbp);
	uc_reg_write(uc, UC_X86_REG_RSP, &reg64.Rsp);

	uc_hook_add(uc, &trace, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT,
		InvalidRwxCallback, &ctx, 1, 0);

	uc_hook_add(uc, &trace2, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH,
		RwxCallback, &ctx, 1, 0);

	uc_hook_add(uc, &trace2, UC_HOOK_CODE,
		CodeDisasmCallback, &ctx, 1, 0);

	err = uc_emu_start(uc, ctx.m_ImageEntry, ctx.m_ImageEnd, 0, 3000000);

	uc_close(uc);

	cs_close(&ctx.m_cs);

	ctx.thisProc.mmap().UnmapAllModules();

	return 0;
}