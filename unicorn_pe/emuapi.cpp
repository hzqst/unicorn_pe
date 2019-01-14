#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <BlackBone/Process/Process.h>
#include <BlackBone/ManualMap/MMap.h>

#include <iostream>
#include <sstream>
#include <fstream>
#include <functional>
#include <vector>
#include <intrin.h>

#include "buffer.h"
#include "encode.h"
#include "nativestructs.h"
#include "ucpe.h"
#include "emuapi.h"

extern std::ostream *outs;

extern "C"
{
	NTSYSAPI NTSTATUS RtlGetVersion(
		PRTL_OSVERSIONINFOW lpVersionInformation
	);
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

void EmuGetSystemTimeAsFileTime(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);

	err = uc_mem_write(uc, rcx, &ft, sizeof(FILETIME));
}

void EmuGetCurrentThreadId(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	DWORD ThreadId = 1024;

	auto err = uc_reg_write(uc, UC_X86_REG_EAX, &ThreadId);
}

void EmuGetCurrentProcessId(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	DWORD ProcessId = 1000;

	auto err = uc_reg_write(uc, UC_X86_REG_EAX, &ProcessId);
}

void EmuQueryPerformanceCounter(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	LARGE_INTEGER li;
	BOOL r = QueryPerformanceCounter(&li);

	err = uc_mem_write(uc, rcx, &li, sizeof(LARGE_INTEGER));

	err = uc_reg_write(uc, UC_X86_REG_EAX, &r);
}

void EmuLoadLibraryExW(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
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
		std::string aDllName;
		UnicodeToANSI(DllName, aDllName);
		*outs << "EmuLoadLibraryExW" << aDllName << "\n";

		ULONG64 ImageBase = 0;
		NTSTATUS st = ctx->LdrFindDllByName(DllName, &ImageBase, NULL, true);
		if (NT_SUCCESS(st))
		{
			r = ImageBase;
		}
	}

	err = uc_reg_write(uc, UC_X86_REG_RAX, &r);
}

void EmuGetProcAddress(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
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
		*outs << "GetProcAddress" << ProcedureName << "\n";

		r = ctx->LdrGetProcAddress(rcx, ProcedureName.c_str());
	}

	err = uc_reg_write(uc, UC_X86_REG_RAX, &r);
}

void EmuGetModuleHandleA(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	std::string ModuleName;
	uint64_t r = 0;
	if (EmuReadNullTermString(uc, rcx, ModuleName))
	{
		*outs << "GetModuleHandleA" << ModuleName << "\n";

		std::wstring wModuleName;
		ANSIToUnicode(ModuleName, wModuleName);
		ctx->LdrFindDllByName(wModuleName, &r, NULL, false);
	}

	err = uc_reg_write(uc, UC_X86_REG_RAX, &r);
}

void EmuGetLastError(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint32_t r = 0;

	auto err = uc_reg_write(uc, UC_X86_REG_EAX, &r);
}

void EmuInitializeCriticalSectionAndSpinCount(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
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

void EmuInitializeCriticalSectionEx(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
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

void EmuTlsAlloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint32_t r = 0;

	auto err = uc_reg_write(uc, UC_X86_REG_EAX, &r);
}

void EmuTlsSetValue(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
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

void EmuTlsFree(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
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

void EmuDeleteCriticalSection(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
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

void EmuLocalAlloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
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

	*outs << "LocalAlloc " << edx << " bytes, allocated at " << std::hex << alloc << "\n";

	err = uc_reg_write(uc, UC_X86_REG_RAX, &alloc);
}

void EmuRtlIsProcessorFeaturePresent(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
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

	*outs << "RtlIsProcessorFeaturePresent feature " << ecx << "\n";

	err = uc_reg_write(uc, UC_X86_REG_AL, &al);
}

void EmuExAllocatePool(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t alloc = 0;

	uint32_t ecx;
	auto err = uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

	uint32_t edx;
	err = uc_reg_read(uc, UC_X86_REG_EDX, &edx);

	alloc = ctx->HeapAlloc(edx);

	*outs << "ExAllocatePool " << edx << " bytes, allocated at " << std::hex << alloc << "\n";

	err = uc_reg_write(uc, UC_X86_REG_RAX, &alloc);
}

void EmuNtQuerySystemInformation(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
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

	if (ecx == (uint32_t)SystemModuleInformation)
		retlen += sizeof(RTL_PROCESS_MODULE_INFORMATION);

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
			newMods->Modules[numberNewMods].ImageBase = (PVOID)ctx->m_ImageBase;
			newMods->Modules[numberNewMods].ImageSize = (ULONG)(ctx->m_ImageEnd - ctx->m_ImageBase);
			newMods->Modules[numberNewMods].LoadCount = 1;
			newMods->Modules[numberNewMods].LoadOrderIndex = newMods->Modules[numberNewMods - 1].LoadOrderIndex + 1;
			numberNewMods++;

			newMods->NumberOfModules = numberNewMods;

			retlen = offsetof(RTL_PROCESS_MODULES, Modules) + sizeof(newMods->Modules[0]) * numberNewMods;

			uc_mem_write(uc, rdx, newMods, retlen);

			free(newMods);

		}
		else if (ecx == (uint32_t)SystemKernelDebuggerInformation)
		{
			SYSTEM_KERNEL_DEBUGGER_INFORMATION info;
			info.DebuggerEnabled = FALSE;
			info.DebuggerNotPresent = TRUE;
			uc_mem_write(uc, rdx, &info, sizeof(info));
		}
	}

	if (r9 != 0)
	{
		uc_mem_write(uc, r9, &retlen, sizeof(retlen));
	}

	free(buf);

	*outs << "NtQuerySystemInformation class " << std::dec << ecx << " return " << std::hex << eax << "\n";

	err = uc_reg_write(uc, UC_X86_REG_EAX, &eax);
}

void EmuExFreePool(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t alloc = 0;

	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	if(!ctx->HeapFree(rcx))
		*outs << "ExFreePool failed to free " << std::hex << rcx << "\n";
	else
		*outs << "ExFreePool free " << std::hex << rcx << "\n";
}

void EmuExFreePoolWithTag(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t alloc = 0;

	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint32_t edx;
	err = uc_reg_read(uc, UC_X86_REG_EDX, &edx);

	if (!ctx->HeapFree(rcx))
		*outs << "ExFreePoolWithTag failed to free " << std::hex << rcx << "\n";	
	else
		*outs << "ExFreePoolWithTag free " << std::hex << rcx << "\n";
}

void EmuIoAllocateMdl(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t alloc = 0;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint32_t edx;
	uc_reg_read(uc, UC_X86_REG_EDX, &edx);

	uint64_t mdl_base = ctx->HeapAlloc(sizeof(MDL));

	MDL mdl = { 0 };
	mdl.Size = sizeof(MDL);
	mdl.ByteCount = edx;
	mdl.StartVa = (PVOID)rcx;
	uc_mem_write(uc, mdl_base, &mdl, sizeof(mdl));

	uc_reg_write(uc, UC_X86_REG_RAX, &mdl_base);

	*outs << "IoAllocateMdl va " << std::hex << rcx << ", len " << std::dec << edx << ", return mdl " << std::hex << mdl_base << "\n";
}

void EmuMmProbeAndLockPages(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint32_t edx;
	uc_reg_read(uc, UC_X86_REG_EDX, &edx);

	uint32_t r8d;
	uc_reg_read(uc, UC_X86_REG_R8D, &r8d);

	*outs << "MmProbeAndLockPages mdl " << std::hex << rcx << ", AccessMode " << std::dec << edx << ", Operation " << std::dec << r8d << "\n";
}

void EmuMmMapLockedPagesSpecifyCache(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint32_t edx;
	uc_reg_read(uc, UC_X86_REG_EDX, &edx);

	uint32_t r8d;
	uc_reg_read(uc, UC_X86_REG_R8D, &r8d);

	uint64_t r9;
	uc_reg_read(uc, UC_X86_REG_R9, &r9);

	MDL mdl = { 0 };
	uc_mem_read(uc, rcx, &mdl, sizeof(mdl));

	uint64_t alloc = ctx->HeapAlloc(mdl.ByteCount, true);

	mdl.MappedSystemVa = (PVOID)alloc;
	uc_mem_write(uc, rcx, &mdl, sizeof(mdl));

	ctx->CreateMemMapping((ULONG64)mdl.StartVa, (ULONG64)mdl.MappedSystemVa, mdl.ByteCount);

	*outs << "MmMapLockedPagesSpecifyCache mdl " << std::hex << rcx << ", AccessMode " << std::dec << edx << 
		", CacheType " << std::dec << r8d << ", RequestedAddress " << std::hex << r9 << "\n";
	*outs << "return va " << std::hex << alloc << "\n";

	uc_reg_write(uc, UC_X86_REG_RAX, &alloc);
}

void EmuKeQueryActiveProcessors(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t ret = 1;

	*outs << "KeQueryActiveProcessors return " << std::dec << ret << "\n";

	uc_reg_write(uc, UC_X86_REG_RAX, &ret);
}

void EmuKeSetSystemAffinityThread(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	*outs << "KeSetSystemAffinityThread Affinity " << std::hex << rcx << "\n";
}

void EmuKeRevertToUserAffinityThread(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	*outs << "KeRevertToUserAffinityThread\n";
}

void EmuMmUnlockPages(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	MDL mdl = { 0 };
	uc_mem_read(uc, rcx, &mdl, sizeof(mdl));

	if(!ctx->HeapFree((ULONG64)mdl.MappedSystemVa))
	{
		*outs << "MmUnlockPages failed to free mapped va " << std::hex << (ULONG64)mdl.MappedSystemVa << "\n";
	}

	ctx->DeleteMemMapping((ULONG64)mdl.MappedSystemVa);

	*outs << "MmUnlockPages mdl " << std::hex << rcx << "\n";
}

void EmuIoFreeMdl(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	ctx->HeapFree(rcx);

	*outs << "IoFreeMdl free " << std::hex << rcx << "\n";
}

void EmuRtlGetVersion(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	RTL_OSVERSIONINFOW verinfo = {0};

	uc_mem_read(uc, rcx, &verinfo, sizeof(verinfo));

	auto st = RtlGetVersion(&verinfo);

	uc_mem_write(uc, rcx, &verinfo, sizeof(verinfo));

	*outs << "RtlGetVersion return " << std::dec << st << "\n";

	uc_reg_write(uc, UC_X86_REG_RAX, &st);
}

void EmuDbgPrint(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint64_t rdx;
	uc_reg_read(uc, UC_X86_REG_RDX, &rdx);

	std::string str, wstra;
	EmuReadNullTermString(uc, rcx, str);

	std::wstring wstr;
	EmuReadNullTermUnicodeString(uc, rdx, wstr);

	UnicodeToANSI(wstr, wstra);

	*outs << "DbgPrint " << str << "\n";
}