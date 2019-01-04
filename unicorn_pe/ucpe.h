#pragma once

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
	AllocBlock_s(ULONG64 b, ULONG s) : base(b), size(s) {
		free = false;
	}
	ULONG64 base;
	ULONG size;
	bool free;
}AllocBlock_t;

typedef struct MemMappingBlock_s
{
	MemMappingBlock_s(ULONG64 v, ULONG64 val, ULONG s) : va(v), value(val), size(s) {

	}
	ULONG64 va;
	ULONG64 value;
	ULONG size;
}MemMappingBlock_t;

typedef struct MemMapping_s
{
	MemMapping_s(ULONG64 b, ULONG64 v, ULONG s) : baseva(b), mappedva(v), size(s) {
		
	}
	ULONG64 baseva;
	ULONG64 mappedva;
	ULONG size;
	std::vector<MemMappingBlock_t> blocks;
}MemMapping_t;

class PeEmulation
{
public:
	PeEmulation()
	{
		m_DisplayDisasm = false;
		m_IsKernel = false;
		m_IsWin64 = true;
		m_TlsValue = -1;
		m_PebBase = 0;
		m_PebEnd = 0;
		m_TebBase = 0;
		m_TebEnd = 0;
		m_DriverObjectBase = 0;
		m_ExecCodeCount = 0;
		m_LastRip = 0;
		m_LastRipModule = 0;
	}

	void InitProcessorState();
	void InitTebPeb();
	void InitKTHREAD();
	void InitDriverObject();
	void InitKSharedUserData();

	void MapImageToEngine(const std::wstring &ImageName, PVOID ImageBase, ULONG ImageSize, ULONG64 MappedBase);
	bool FindAddressInRegion(ULONG64 address, std::stringstream &RegionName);
	bool WriteMemMapping(ULONG64 baseaddress, ULONG64 value, ULONG size);
	bool FindAPIByAddress(ULONG64 address, std::wstring &DllName, FakeAPI_t **api);
	bool FindModuleByAddress(ULONG64 address, ULONG64 &DllBase);
	bool RegisterAPIEmulation(const std::wstring &DllName, const char *ProcedureName, void *callback, int argsCount);
	void AddAPIEmulation(FakeAPI_t *r, void *callback, int argsCount);

	VOID LdrResolveExportTable(FakeModule_t *module, PVOID ImageBase, ULONG64 MappedBase);
	ULONG64 LdrGetProcAddress(ULONG64 ImageBase, const char *ProcedureName);
	NTSTATUS LdrFindDllByName(const std::wstring &DllName, ULONG64 *ImageBase, ULONG *ImageSize, bool LoadIfNotExist);
	NTSTATUS LdrLoadDllByName(const std::wstring &DllName, ULONG64 *ImageBase, ULONG *ImageSize);

	ULONG64 HeapAlloc(ULONG Bytes, bool IsPageAlign = false);
	bool HeapFree(ULONG64 FreeAddress);
	bool CreateMemMapping(ULONG64 BaseAddress, ULONG64 MapAddress, ULONG Bytes);
	void DeleteMemMapping(ULONG64 MapAddress);
public:
	blackbone::Process thisProc;
	csh m_cs;
	uc_engine *m_uc;
	bool m_IsWin64;
	bool m_IsKernel;
	bool m_DisplayDisasm;

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
	uint64_t m_KThreadBase;

	std::vector<FakeModule_t *> m_FakeModules;
	std::vector<AllocBlock_t> m_HeapAllocs;
	std::vector<MemMapping_t> m_MemMappings;
	uint64_t m_TlsValue;
	uint64_t m_LastRip;
	uint64_t m_LastRipModule;
	uint64_t m_ExecCodeCount;
};

#define API_FUNCTION_SIZE 8
#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(Va) (ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)
#define PAGE_ALIGN_64(Va) (Va) & ~(0x1000ull - 1)
#define PAGE_ALIGN_64k(Va) ((Va)) & ~(0x10000ull - 1)

#define AlignSize(Size, Align) (Size+Align-1)/Align*Align