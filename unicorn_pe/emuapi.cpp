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

		ULONG64 ImageBase = 0;
		NTSTATUS st = ctx->LdrFindDllByName(DllName, &ImageBase, NULL, true);
		if (NT_SUCCESS(st))
		{
			r = ImageBase;
		}

		*outs << "LoadLibraryExW " << aDllName << ", return " << std::hex << r << "\n";
	}

	err = uc_reg_write(uc, UC_X86_REG_RAX, &r);
}

void EmuLoadLibraryA(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint64_t rdx;
	err = uc_reg_read(uc, UC_X86_REG_RDX, &rdx);

	uint32_t r8d;
	err = uc_reg_read(uc, UC_X86_REG_R8D, &r8d);

	std::string DllName;
	uint64_t r = 0;
	if (EmuReadNullTermString(uc, rcx, DllName))
	{
		std::wstring wDllName;
		ANSIToUnicode(DllName, wDllName);

		ULONG64 ImageBase = 0;
		NTSTATUS st = ctx->LdrFindDllByName(wDllName, &ImageBase, NULL, true);
		if (NT_SUCCESS(st))
		{
			r = ImageBase;
		}

		*outs << "LoadLibraryA " << DllName << ", return " << std::hex << r << "\n";
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
		r = ctx->LdrGetProcAddress(rcx, ProcedureName.c_str());

		*outs << "GetProcAddress " << ProcedureName << ", return " << std::hex << r << "\n";
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
		std::wstring wModuleName;
		ANSIToUnicode(ModuleName, wModuleName);
		ctx->LdrFindDllByName(wModuleName, &r, NULL, false);

		*outs << "GetModuleHandleA " << ModuleName << ", return " << r << "\n";
	}

	err = uc_reg_write(uc, UC_X86_REG_RAX, &r);
}

void EmuGetLastError(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint32_t r = 0;

	auto err = uc_reg_write(uc, UC_X86_REG_EAX, &r);

	*outs << "GetLastError return " << r << "\n";
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

	*outs << "InitializeCriticalSectionAndSpinCount " << rcx << "\n";
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

	*outs << "InitializeCriticalSectionEx " << rcx << "\n";
}

void EmuTlsAlloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	uint32_t r = 0;

	auto err = uc_reg_write(uc, UC_X86_REG_EAX, &r);

	*outs << "TlsAlloc return " << r << "\n";
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

	*outs << "TlsSetValue " << ecx << "\n";
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

	*outs << "TlsFree " << ecx << "\n";
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

	*outs << "DeleteCriticalSection " << rcx << "\n";
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

void EmuGetProcessAffinityMask(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint32_t eax = 0;

	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint64_t rdx;
	err = uc_reg_read(uc, UC_X86_REG_RDX, &rdx);

	uint64_t r8;
	err = uc_reg_read(uc, UC_X86_REG_R8, &r8);

	if (rcx == (uint64_t)-1)
	{
		eax = 1;

		DWORD_PTR ProcessAffinityMask =0;
		DWORD_PTR SystemAffinityMask = 0;

		uc_mem_write(uc, rdx, &ProcessAffinityMask, sizeof(ProcessAffinityMask));
		uc_mem_write(uc, r8, &SystemAffinityMask, sizeof(SystemAffinityMask));
	}

	*outs << "GetProcessAffinityMask handle " << rcx << "\n";

	err = uc_reg_write(uc, UC_X86_REG_EAX, &eax);
}

void EmuExAllocatePool(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t alloc = 0;

	uint32_t ecx;
	auto err = uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

	uint32_t edx;
	err = uc_reg_read(uc, UC_X86_REG_EDX, &edx);

	alloc = ctx->HeapAlloc(edx, edx >= PAGE_SIZE);

	*outs << "ExAllocatePool " << edx << " bytes, allocated at " << std::hex << alloc << "\n";

	err = uc_reg_write(uc, UC_X86_REG_RAX, &alloc);
}

void EmuNtProtectVirtualMemory(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	auto err = uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint64_t rdx;
	err = uc_reg_read(uc, UC_X86_REG_RDX, &rdx);

	uint64_t r8;
	err = uc_reg_read(uc, UC_X86_REG_R8, &r8);

	uint32_t r9d;
	err = uc_reg_read(uc, UC_X86_REG_R9D, &r9d);

	uint64_t rsp;
	err = uc_reg_read(uc, UC_X86_REG_RSP, &rsp);

	uint64_t oldprot;

	uc_mem_read(uc, rsp + 5 * 8, &oldprot, sizeof(oldprot));

	NTSTATUS status;

	if (rcx == (uint64_t)-1)
	{
		uint64_t RequestAddress, BaseAddress, EndAddress;
		uint32_t NumberOfBytes;

		uc_mem_read(uc, rdx, &RequestAddress, sizeof(BaseAddress));
		uc_mem_read(uc, r8, &NumberOfBytes, sizeof(NumberOfBytes));

		EndAddress = RequestAddress + NumberOfBytes - 1;
		BaseAddress = PAGE_ALIGN(RequestAddress);
		EndAddress = AlignSize(EndAddress, PAGE_SIZE);

		int prot = 0;

		if (r9d == PAGE_EXECUTE_READWRITE)
			prot = UC_PROT_ALL;
		else if (r9d == PAGE_EXECUTE_READ)
			prot = (UC_PROT_READ | UC_PROT_EXEC);
		else if (r9d == PAGE_READWRITE)
			prot = (UC_PROT_READ | UC_PROT_WRITE);
		else if (r9d == PAGE_READONLY)
			prot = UC_PROT_READ;
		else
			status = STATUS_INVALID_PARAMETER;

		if (prot != 0)
		{
			uc_mem_region *regions;
			uint32_t count;
			err = uc_mem_regions(uc, &regions, &count);

			for (uint32_t i = 0; i < count; ++i)
			{
				if (regions[i].begin <= BaseAddress && regions[i].end >= BaseAddress)
				{
					if (regions[i].perms == UC_PROT_ALL)
						oldprot = PAGE_EXECUTE_READWRITE;
					else if (regions[i].perms == (UC_PROT_READ | UC_PROT_EXEC))
						oldprot = PAGE_EXECUTE_READ;
					else if (regions[i].perms == (UC_PROT_READ | UC_PROT_WRITE))
						oldprot = PAGE_READWRITE;
					else if (regions[i].perms == UC_PROT_READ)
						oldprot = PAGE_READONLY;

					break;
				}
			}
			uc_free(regions);

			uc_mem_write(uc, rsp + 5 * 8, &oldprot, sizeof(oldprot));

			err = uc_mem_protect(uc, BaseAddress, EndAddress - BaseAddress, prot);

			if(err == UC_ERR_OK)
				status = STATUS_SUCCESS;
			else
				status = STATUS_INVALID_PARAMETER;

			*outs << "NtProtectVirtualMemory at " << RequestAddress;
			
			std::stringstream region;
			if (ctx->FindAddressInRegion(RequestAddress, region))
				*outs << " (" << region.str() << ")";
			*outs << ", size " << NumberOfBytes << " bytes, return " << std::hex << status << "\n";
		}
	}
	else
	{
		status = STATUS_INVALID_HANDLE;
	}

	uc_reg_write(uc, UC_X86_REG_EAX, &status);
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
	
	auto rax = (uint64_t)NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)ecx, buf, r8d, &retlen);

	if (ecx == (uint32_t)SystemModuleInformation)
		retlen += sizeof(RTL_PROCESS_MODULE_INFORMATION);

	if (ecx == (uint32_t)SystemFirmwareTableInformation)
	{
		retlen = 0;
		rax = STATUS_ACCESS_DENIED;
	}

	if (rax == STATUS_INFO_LENGTH_MISMATCH)
	{
		
	}
	else if (rax == STATUS_SUCCESS)
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

	*outs << "NtQuerySystemInformation class " << std::dec << ecx << " return " << std::hex << rax << "\n";

	//VMProtect 2.x use rax as ntstatus result 
	uc_reg_write(uc, UC_X86_REG_RAX, &rax);
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

	ctx->DeleteMemMapping((ULONG64)mdl.MappedSystemVa);

	if(!ctx->HeapFree((ULONG64)mdl.MappedSystemVa))
	{
		*outs << "MmUnlockPages failed to free mapped va " << std::hex << (ULONG64)mdl.MappedSystemVa << "\n";
	}

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

void EmuKeInitializeMutex(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint32_t edx;
	uc_reg_read(uc, UC_X86_REG_EDX, &edx);

	*outs << "KeInitializeMutex Mutex " << std::hex << rcx << ", level " << edx << "\n";
}

void EmuRtlInitUnicodeString(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint64_t rdx;
	uc_reg_read(uc, UC_X86_REG_RDX, &rdx);

	std::wstring wstr;
	EmuReadNullTermUnicodeString(uc, rdx, wstr);

	std::string str;
	UnicodeToANSI(wstr, str);

	UNICODE_STRING ustr;
	ustr.Buffer = (PWCH)rdx;
	ustr.Length = (USHORT)wstr.length() * sizeof(WCHAR);
	ustr.MaximumLength = (USHORT)(wstr.length() + 1) * sizeof(WCHAR);

	uc_mem_write(uc, rcx, &ustr, sizeof(ustr));

	*outs << "RtlInitUnicodeString DestString " << std::hex << rcx << ", SourceString " << str << "\n";
}

void EmuKeWaitForSingleObject(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint32_t edx;
	uc_reg_read(uc, UC_X86_REG_EDX, &edx);

	uint8_t r8b;
	uc_reg_read(uc, UC_X86_REG_R8B, &r8b);

	uint8_t r9b;
	uc_reg_read(uc, UC_X86_REG_R9B, &r9b);

	*outs << "KeWaitForSingleObject Object " << std::hex << rcx << ", WaitReason " << edx << ", WaitMode " << (int)r8b << ", Alertable " << (int)r9b << "\n";
}

void EmuKeReleaseMutex(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint8_t dl;
	uc_reg_read(uc, UC_X86_REG_DL, &dl);

	*outs << "KeReleaseMutex Object " << std::hex << rcx << ", Wait " << (int)dl << "\n";
}

void Emusrand(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint32_t ecx;
	uc_reg_read(uc, UC_X86_REG_ECX, &ecx);

	srand((unsigned int)ecx);

	*outs << "srand " << ecx << "\n";
}

void Emurand(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	int eax = rand();

	*outs << "rand return " << eax << "\n";
}

void EmuRtlZeroMemory(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint64_t rdx;
	uc_reg_read(uc, UC_X86_REG_RDX, &rdx);

	virtual_buffer_t temp(rdx);
	uc_mem_write(uc, rcx, temp.GetBuffer(), rdx);

	*outs << "RtlZeroMemory " << std::hex << rcx << ", len " << rdx << "\n";
}

void EmuRtlFillMemory(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint64_t rdx;
	uc_reg_read(uc, UC_X86_REG_RDX, &rdx);

	uint8_t r8b;
	uc_reg_read(uc, UC_X86_REG_R8B, &r8b);

	virtual_buffer_t temp(rdx);
	memset(temp.GetBuffer(), r8b, rdx);
	uc_mem_write(uc, rcx, temp.GetBuffer(), rdx);

	*outs << "RtlFillMemory " << std::hex << rcx << ", len " << rdx << ", ch " << (int)r8b << "\n";
}

void EmuRtlCopyMemory(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint64_t rdx;
	uc_reg_read(uc, UC_X86_REG_RDX, &rdx);

	uint64_t r8;
	uc_reg_read(uc, UC_X86_REG_R8, &r8);

	virtual_buffer_t temp(r8);
	uc_mem_read(uc, rdx, temp.GetBuffer(), r8);
	uc_mem_write(uc, rcx, temp.GetBuffer(), r8);

	uc_reg_write(uc, UC_X86_REG_RAX, &rcx);

	*outs << "RtlCopyMemory dst " << std::hex << rcx << ", src "<< rdx << ", len " << r8 << "\n";
}

void Emuwcsstr(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint64_t rdx;
	uc_reg_read(uc, UC_X86_REG_RDX, &rdx);

	std::wstring wstr1, wstr2;
	EmuReadNullTermUnicodeString(uc, rcx, wstr1);
	EmuReadNullTermUnicodeString(uc, rdx, wstr2);

	std::string str1, str2;
	UnicodeToANSI(wstr1, str1);
	UnicodeToANSI(wstr2, str2);

	auto ptr = wcsstr(wstr1.c_str(), wstr2.c_str());

	uint64_t rax = ptr ? ((char *)ptr - (char *)wstr1.c_str()) + rcx : 0;

	uc_reg_write(uc, UC_X86_REG_RAX, &rax);

	*outs << "wcsstr String1 " << std::hex << rcx << " " << str1 
		<< ", String2 " << rdx << " " << str2
		<< ", return " << rax << "\n";
}

void EmuMmIsAddressValid(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint64_t rcx;
	uc_reg_read(uc, UC_X86_REG_RCX, &rcx);

	uint8_t test;
	auto err = uc_mem_read(uc, rcx, &test, 1);

	uint8_t al = (err == UC_ERR_READ_UNMAPPED) ? 0 : 1;

	uc_reg_write(uc, UC_X86_REG_AL, &al);

	*outs << "MmIsAddressValid address " << std::hex << rcx << ", return " << (int)al << "\n";
}

void EmuExGetPreviousMode(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	uint32_t eax = 0;
	uc_reg_write(uc, UC_X86_REG_EAX, &eax);

	*outs << "ExGetPreviousMode return " << std::hex << eax << "\n";
}

void Emu__C_specific_handler(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	PeEmulation *ctx = (PeEmulation *)user_data;

	ctx->m_ExecuteExceptionHandler = 1;

	uc_emu_stop(uc);
}