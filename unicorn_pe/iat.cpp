#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <BlackBone/Process/Process.h>
#include <BlackBone/ManualMap/MMap.h>
#include <BlackBone/Patterns/PatternSearch.h>

#include <iostream>
#include <sstream>
#include <fstream>
#include <functional>
#include <algorithm>
#include <vector>
#include <intrin.h>

#include "buffer.h"
#include "encode.h"
#include "nativestructs.h"
#include "ucpe.h"
#include "emuapi.h"
#include "iat.h"

extern "C"
{
	NTSYSAPI
		PIMAGE_NT_HEADERS
		NTAPI
		RtlImageNtHeader(IN PVOID BaseAddress);
}

extern std::ostream *outs;

void PeEmulation::DisasmFunction(ULONG64 FunctionBegin, ULONG64 FunctionEnd, const disasm_callback &callback)
{
	crt_buffer_t buf;

	if (FunctionEnd < FunctionBegin)
		return;

	SIZE_T FunctionLength = (PUCHAR)FunctionEnd - (PUCHAR)FunctionBegin;

	auto pbuf = buf.GetSpace(FunctionLength);

	uc_mem_read(m_uc, FunctionBegin, pbuf, FunctionLength);

	auto code = (uint8_t * )pbuf;
	cs_insn *insn = NULL;
	auto count = cs_disasm(m_cs, code, FunctionLength, FunctionBegin, 10000, &insn);
	if (insn)
	{
		for (size_t i = 0; i < count; ++i)
		{
			if (callback(&insn[i], insn[i].address, insn[i].size, i))
				break;
		}
		cs_free(insn, count);
	}
}

bool PeEmulation::RebuildSection(PVOID ImageBase, ULONG ImageSize, virtual_buffer_t &RebuildSectionBuffer)
{
	using namespace blackbone;

	PatternSearch patternFF15("\xFF\x15");
	PatternSearch patternFF25("\xFF\x25");
	PatternSearch patternVMPDecryptString("\x48\x8D\x0D\x2A\x2A\x2A\x2A\xE8\x2A\x2A\x2A\x2A\x90");
	PatternSearch patternVMPCallAPI("\xE8\x2A\x2A\x2A\x2A");

	rebuildiat_dlls dlls;
	std::vector<ptr_t> outIAT, outVMPStr, outVMPCall;
	std::wstring dllnamew;
	std::string dllname;

	std::vector<vmpstr_dec> vmpstrs;
	std::vector<vmpcall_dec> vmpcalls;

	size_t RebuildSize = 0, RebuildIATDescSize = 0;	
	int RebuildIATRva = 0;
	int NewIATRva = ImageSize;

	auto ntheader = (PIMAGE_NT_HEADERS)RtlImageNtHeader(ImageBase);

	auto SectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)ntheader + sizeof(ntheader->Signature) + \
		sizeof(ntheader->FileHeader) + ntheader->FileHeader.SizeOfOptionalHeader);

	auto SectionCount = ntheader->FileHeader.NumberOfSections;

	for (USHORT i = 0; i < SectionCount; ++i)
	{
		if (SectionHeader[i].Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))
		{
			if (!memcmp(SectionHeader[i].Name, ".text\0\0\0", 8) ||
				!memcmp(SectionHeader[i].Name, "INIT\0\0\0\0", 8) ||
				!memcmp(SectionHeader[i].Name, "PAGE\0\0\0\0", 8))
			{
				patternFF15.Search((PUCHAR)ImageBase + SectionHeader[i].VirtualAddress,
					SectionHeader[i].Misc.VirtualSize, outIAT);

				patternFF25.Search((PUCHAR)ImageBase + SectionHeader[i].VirtualAddress,
					SectionHeader[i].Misc.VirtualSize, outIAT);

				patternVMPDecryptString.Search((uint8_t)0x2A, (PUCHAR)ImageBase + SectionHeader[i].VirtualAddress,
					SectionHeader[i].Misc.VirtualSize, outVMPStr);

				patternVMPCallAPI.Search((uint8_t)0x2A, (PUCHAR)ImageBase + SectionHeader[i].VirtualAddress,
					SectionHeader[i].Misc.VirtualSize, outVMPCall);
			}
		}
	}

	for (size_t j = 0; j < outIAT.size(); ++j)
	{
		//fix IAT
		int insn_rva = (int)(outIAT[j] - (ptr_t)ImageBase);
		int call_rva = insn_rva + *(int *)(outIAT[j] + 2) + 6;
		if (call_rva >= 0 && call_rva < (int)ImageSize)
		{
			auto call_api_addr = *(ULONG_PTR *)((PUCHAR)ImageBase + call_rva);

			FakeAPI_t *api_ptr = NULL;
			if (FindAPIByAddress(call_api_addr, dllnamew, &api_ptr))
			{
				UnicodeToANSI(dllnamew, dllname);
				std::transform(dllname.begin(), dllname.end(), dllname.begin(), ::tolower);

				auto dll_itor = dlls.find(dllname);
				rebuildiat_apis *apis = NULL;
				if (dll_itor != dlls.end())
				{
					apis = dll_itor->second;
				}
				else
				{
					apis = new rebuildiat_apis;
					dlls.insert_or_assign(dllname, apis);
				}

				bool bInserted = false;
				for (size_t t = 0; t < apis->apis.size(); ++t)
				{
					if (apis->apis[t].funcname == api_ptr->ProcedureName)
					{
						apis->apis[t].rvaFF15.emplace(insn_rva);
						bInserted = true;
						break;
					}
				}

				if (!bInserted)
				{
					rebuildiat_api api;
					api.funcname = api_ptr->ProcedureName;
					api.rvaFF15.emplace(insn_rva);
					apis->apis.emplace_back(api);
				}

				*outs << "found IAT 0x" << std::hex << insn_rva << " to " << api_ptr->ProcedureName << "\n";
			}
		}
	}

	for (size_t j = 0; j < outVMPStr.size(); ++j)
	{
		int insn_rva = (int)(outVMPStr[j] - (ptr_t)ImageBase);
		int encrypt_string_rva = insn_rva + *(int *)(outVMPStr[j] + 3) + 7;
		if (encrypt_string_rva >= 0 && encrypt_string_rva < (int)ImageSize)
		{
			auto engine_encrypt_string_addr = (ULONG_PTR)m_ImageBase + encrypt_string_rva;

			int call_rva = insn_rva + *(int *)(outVMPStr[j] + 8) + 12;
			if (call_rva >= 0 && call_rva < (int)ImageSize)
			{
				auto engine_call_addr = (ULONG_PTR)m_ImageBase + call_rva;

				FakeSection_t *encrypt_string_section = NULL;
				FakeSection_t *call_addr_section = NULL;
				if (FindSectionByAddress(engine_encrypt_string_addr, &encrypt_string_section) &&
					FindSectionByAddress(engine_call_addr, &call_addr_section) &&
					!encrypt_string_section->IsUnknownSection && 
					call_addr_section->IsUnknownSection)
				{
					vmpstrs.emplace_back(insn_rva, encrypt_string_rva, call_rva);
				}
			}
		}
	}

	for (size_t j = 0; j < outVMPCall.size(); ++j)
	{
		int insn_rva = (int)(outVMPCall[j] - (ptr_t)ImageBase);
		int call_target_rva = insn_rva + *(int *)(outVMPCall[j] + 1) + 5;
		if (call_target_rva >= 0 && call_target_rva < (int)ImageSize)
		{
			auto call_target_addr = (ULONG_PTR)m_ImageBase + call_target_rva;

			FakeSection_t *call_addr_section = NULL;
			if (FindSectionByAddress(call_target_addr, &call_addr_section) && call_addr_section)
			{
				if (0 == memcmp(call_addr_section->SectionName, ".text\0\0\0", 0)
					|| 0 == memcmp(call_addr_section->SectionName, "INIT\0\0\0\0", 0)
					|| 0 == memcmp(call_addr_section->SectionName, "PAGE\0\0\0\0", 0))
				{
					DWORD64 ImageBase64 = 0;
					auto FunctionEntryPtr = RtlpLookupFunctionEntry(call_target_addr, &ImageBase64, NULL);
					if (FunctionEntryPtr)
					{
						RUNTIME_FUNCTION FunctionEntry;
						uc_mem_read(m_uc, (uint64_t)FunctionEntryPtr, &FunctionEntry, sizeof(FunctionEntry));		
						ULONG64 FunctionBegin = ImageBase64 + FunctionEntry.BeginAddress;
						ULONG64 FunctionEnd = ImageBase64 + FunctionEntry.EndAddress;
						if (FunctionBegin == call_target_addr)
						{
							//it's part of normal function entry, ignore
							printf("0x%x call to 0x%x to part of normal function entry, ignore.\n", insn_rva, call_target_addr);
							continue;
						}
					}
				}

				bool default_rva = true;

				UCHAR first_bytes[8] = { 0 };
				uc_mem_read(m_uc, m_ImageBase + insn_rva - 2, first_bytes, 8);
				if (first_bytes[1] >= 0x50 && first_bytes[1] <= 0x57)
				{
					if (first_bytes[0] == 0x48)
					{
						bool isValidInsn = false;
						DWORD64 ImageBase64 = 0;
						auto FunctionEntryPtr = RtlpLookupFunctionEntry(m_ImageBase + insn_rva - 2, &ImageBase64, NULL);
						if (FunctionEntryPtr)
						{
							RUNTIME_FUNCTION FunctionEntry;
							uc_mem_read(m_uc, (uint64_t)FunctionEntryPtr, &FunctionEntry, sizeof(FunctionEntry));
							ULONG64 FunctionBegin = ImageBase64 + FunctionEntry.BeginAddress;
							ULONG64 FunctionEnd = ImageBase64 + FunctionEntry.EndAddress;
							DisasmFunction(FunctionBegin, FunctionEnd, [&isValidInsn, this, insn_rva](cs_insn *inst, uint64_t pAddress, size_t instLen, int instCount) {
								if (pAddress == m_ImageBase + insn_rva - 2)
								{
									isValidInsn = true;
									return true;
								}
								return false;
							});
						}
						else
						{
							isValidInsn = true;
						}
						if(isValidInsn)
						{
							vmpcalls.emplace_back(insn_rva - 2, call_target_rva);
							printf("0x%x vmpcall to 0x%x recorded.\n", insn_rva - 2, call_target_addr);
							default_rva = false;
						}
					}
					else
					{
						bool isValidInsn = false;
						DWORD64 ImageBase64 = 0;
						auto FunctionEntryPtr = RtlpLookupFunctionEntry(m_ImageBase + insn_rva - 1, &ImageBase64, NULL);
						if (FunctionEntryPtr)
						{
							RUNTIME_FUNCTION FunctionEntry;
							uc_mem_read(m_uc, (uint64_t)FunctionEntryPtr, &FunctionEntry, sizeof(FunctionEntry));
							ULONG64 FunctionBegin = ImageBase64 + FunctionEntry.BeginAddress;
							ULONG64 FunctionEnd = ImageBase64 + FunctionEntry.EndAddress;
							DisasmFunction(FunctionBegin, FunctionEnd, [&isValidInsn, this, insn_rva](cs_insn *inst, uint64_t pAddress, size_t instLen, int instCount) {
								if (pAddress == m_ImageBase + insn_rva - 1)
								{
									isValidInsn = true;
									return true;
								}
								return false;
							});
						}
						else
						{
							isValidInsn = true;
						}

						if (isValidInsn)
						{
							vmpcalls.emplace_back(insn_rva - 1, call_target_rva);
							printf("0x%x vmpcall to 0x%x recorded.\n", insn_rva - 1, call_target_addr);
							default_rva = false;
						}
					}
				}
				else if (first_bytes[1] == 0x48 && first_bytes[2] == 0xE8)
				{
					//48 E8 7E AF 1F 00 call    loc_140204945
					bool isValidInsn = false;
					DWORD64 ImageBase64 = 0;
					auto FunctionEntryPtr = RtlpLookupFunctionEntry(m_ImageBase + insn_rva - 1, &ImageBase64, NULL);
					if (FunctionEntryPtr)
					{
						RUNTIME_FUNCTION FunctionEntry;
						uc_mem_read(m_uc, (uint64_t)FunctionEntryPtr, &FunctionEntry, sizeof(FunctionEntry));
						ULONG64 FunctionBegin = ImageBase64 + FunctionEntry.BeginAddress;
						ULONG64 FunctionEnd = ImageBase64 + FunctionEntry.EndAddress;
						DisasmFunction(FunctionBegin, FunctionEnd, [&isValidInsn, this, insn_rva](cs_insn *inst, uint64_t pAddress, size_t instLen, int instCount) {
							if (pAddress == m_ImageBase + insn_rva - 1)
							{
								isValidInsn = true;
								return true;
							}
							return false;
						});
					}
					else
					{
						isValidInsn = true;
					}

					if (isValidInsn)
					{
						vmpcalls.emplace_back(insn_rva - 1, call_target_rva);
						printf("0x%x vmpcall to 0x%x recorded.\n", insn_rva - 1, call_target_addr);
						default_rva = false;
					}
				}

				if(default_rva)
				{
					vmpcalls.emplace_back(insn_rva, call_target_rva);
					printf("0x%x vmpcall to 0x%x recorded.\n", insn_rva, call_target_addr);
				}
			}
		}
	}

	for (size_t j = 0; j < vmpstrs.size(); ++j)
	{
		uint64_t rsp = m_StackEnd - 64;
		uc_reg_write(m_uc, UC_X86_REG_RSP, &rsp);

		auto call_entry = m_ImageBase + vmpstrs[j].insn_rva;
		auto call_end = call_entry + 13;
		auto err = uc_emu_start(m_uc, call_entry, call_end, 0, 0);

		if (err == UC_ERR_OK)
		{
			uint64_t rax = 0;
			uc_reg_read(m_uc, UC_X86_REG_RAX, &rax);
			
			char last2Bytes[2];
			uc_mem_read(m_uc, rax + m_LastHeapAllocBytes - 2, last2Bytes, 2);

			if (last2Bytes[0] != '\0' && last2Bytes[1] == '\0')
			{
				std::string str;
				str.resize(m_LastHeapAllocBytes / 2);
				uc_mem_read(m_uc, rax, str.data(), m_LastHeapAllocBytes - 1);

				vmpstrs[j].bytes.resize(m_LastHeapAllocBytes);
				memcpy(vmpstrs[j].bytes.data(), str.data(), m_LastHeapAllocBytes);

				*outs << std::hex << call_entry << " call VMProtectDecryptStringA " << str << "\n";
			}
			else if (last2Bytes[0] == '\0' && last2Bytes[1] == '\0')
			{
				std::wstring wstr;
				wstr.resize(m_LastHeapAllocBytes/2);
				uc_mem_read(m_uc, rax, wstr.data(), m_LastHeapAllocBytes - 2);

				vmpstrs[j].bytes.resize(m_LastHeapAllocBytes);
				memcpy(vmpstrs[j].bytes.data(), wstr.data(), m_LastHeapAllocBytes);

				std::string str;
				UnicodeToANSI(wstr, str);
				*outs << std::hex << call_entry << " call VMProtectDecryptStringW " << str << "\n";
			}
		}
	}

	m_FakeAPICallEnabled = true;
	virtual_buffer_t stack_buf(m_StackEnd - m_StackBase);

	for (size_t j = 0; j < vmpcalls.size(); ++j)
	{
		m_LastFakeAPICall = NULL;
		m_LastFakeAPICallReturnAddress = 0;

		uint64_t call_entry = m_ImageBase + vmpcalls[j].insn_rva;
		uint64_t call_ret = m_ImageBase + vmpcalls[j].insn_rva + 5;
		CONTEXT tempCtx;

		memset(&tempCtx, 0, sizeof(tempCtx));

		tempCtx.Rsp = m_StackEnd - 0x1000;		
		tempCtx.Rax = 1;
		tempCtx.Rbx = 2;
		tempCtx.Rcx = 3;
		tempCtx.Rdx = 4;
		tempCtx.Rdi = 5;
		tempCtx.Rsi = 6;
		tempCtx.Rbp = 7;
		tempCtx.R8 = 8;
		tempCtx.R9 = 9;
		tempCtx.R10 = 10;
		tempCtx.R11 = 11;
		tempCtx.R12 = 12;
		tempCtx.R13 = 13;
		tempCtx.R14 = 14;
		tempCtx.R15 = 15;
		uc_reg_write(m_uc, UC_X86_REG_RAX, &tempCtx.Rax);
		uc_reg_write(m_uc, UC_X86_REG_RBX, &tempCtx.Rbx);
		uc_reg_write(m_uc, UC_X86_REG_RCX, &tempCtx.Rcx);
		uc_reg_write(m_uc, UC_X86_REG_RDX, &tempCtx.Rdx);
		uc_reg_write(m_uc, UC_X86_REG_RSI, &tempCtx.Rsi);
		uc_reg_write(m_uc, UC_X86_REG_RDI, &tempCtx.Rdi);
		uc_reg_write(m_uc, UC_X86_REG_R8,  &tempCtx.R8);
		uc_reg_write(m_uc, UC_X86_REG_R9,  &tempCtx.R9);
		uc_reg_write(m_uc, UC_X86_REG_R10, &tempCtx.R10);
		uc_reg_write(m_uc, UC_X86_REG_R11, &tempCtx.R11);
		uc_reg_write(m_uc, UC_X86_REG_R12, &tempCtx.R12);
		uc_reg_write(m_uc, UC_X86_REG_R13, &tempCtx.R13);
		uc_reg_write(m_uc, UC_X86_REG_R14, &tempCtx.R14);
		uc_reg_write(m_uc, UC_X86_REG_R15, &tempCtx.R15);
		uc_reg_write(m_uc, UC_X86_REG_RBP, &tempCtx.Rbp);
		uc_reg_write(m_uc, UC_X86_REG_RSP, &tempCtx.Rsp);

		memset(stack_buf.GetBuffer(), 0, stack_buf.GetLength());
		uc_mem_write(m_uc, m_StackBase, stack_buf.GetBuffer(), m_StackEnd - m_StackBase);

		auto err = uc_emu_start(m_uc, call_entry, call_ret, 0, 50);

		uc_reg_read(m_uc, UC_X86_REG_RAX, &tempCtx.Rax);
		uc_reg_read(m_uc, UC_X86_REG_RBX, &tempCtx.Rbx);
		uc_reg_read(m_uc, UC_X86_REG_RCX, &tempCtx.Rcx);
		uc_reg_read(m_uc, UC_X86_REG_RDX, &tempCtx.Rdx);
		uc_reg_read(m_uc, UC_X86_REG_RSI, &tempCtx.Rsi);
		uc_reg_read(m_uc, UC_X86_REG_RDI, &tempCtx.Rdi);
		uc_reg_read(m_uc, UC_X86_REG_R8, &tempCtx.R8);
		uc_reg_read(m_uc, UC_X86_REG_R9, &tempCtx.R9);
		uc_reg_read(m_uc, UC_X86_REG_R10, &tempCtx.R10);
		uc_reg_read(m_uc, UC_X86_REG_R11, &tempCtx.R11);
		uc_reg_read(m_uc, UC_X86_REG_R12, &tempCtx.R12);
		uc_reg_read(m_uc, UC_X86_REG_R13, &tempCtx.R13);
		uc_reg_read(m_uc, UC_X86_REG_R14, &tempCtx.R14);
		uc_reg_read(m_uc, UC_X86_REG_R15, &tempCtx.R15);
		uc_reg_read(m_uc, UC_X86_REG_RBP, &tempCtx.Rbp);
		uc_reg_read(m_uc, UC_X86_REG_RSP, &tempCtx.Rsp);
		
		if (tempCtx.Rax != 1)
		{
			printf("Failed to handle vmpcall 0x%x due to Rax mismatch.\n", vmpcalls[j].insn_rva);
			continue;
		}
		else if (tempCtx.Rbx != 2)
		{
			printf("Failed to handle vmpcall 0x%x due to Rbx mismatch.\n", vmpcalls[j].insn_rva);
			continue;
		}
		else if (tempCtx.Rcx != 3)
		{
			printf("Failed to handle vmpcall 0x%x due to Rcx mismatch.\n", vmpcalls[j].insn_rva);
			continue;
		}
		else if (tempCtx.Rdx != 4)
		{
			printf("Failed to handle vmpcall 0x%x due to Rdx mismatch.\n", vmpcalls[j].insn_rva);
			continue;
		}
		else if (tempCtx.Rdi != 5)
		{
			printf("Failed to handle vmpcall 0x%x due to Rdi mismatch.\n", vmpcalls[j].insn_rva);
			continue;
		}
		else if (tempCtx.Rsi != 6)
		{
			printf("Failed to handle vmpcall 0x%x due to Rsi mismatch.\n", vmpcalls[j].insn_rva);
			continue;
		}
		else if (tempCtx.Rbp != 7)
		{
			printf("Failed to handle vmpcall 0x%x due to Rbp mismatch.\n", vmpcalls[j].insn_rva);
			continue;
		}

		if (err == UC_ERR_OK && m_LastFakeAPICall
			&& (
			((m_LastFakeAPICallReturnAddress == call_ret || m_LastFakeAPICallReturnAddress == call_ret + 1) && tempCtx.Rsp + sizeof(uint64_t) == m_StackEnd - 0x1000)
			||
			(m_LastFakeAPICallReturnAddress == 0 && tempCtx.Rsp == m_StackEnd - 0x1000)
			)
		)
		{
			FakeAPI_t *api_ptr = NULL;
			if (FindAPIByAddress(m_LastFakeAPICall->VirtualAddress, dllnamew, &api_ptr))
			{
				UnicodeToANSI(dllnamew, dllname);
				std::transform(dllname.begin(), dllname.end(), dllname.begin(), ::tolower);

				auto dll_itor = dlls.find(dllname);
				rebuildiat_apis *apis = NULL;
				if (dll_itor != dlls.end())
				{
					apis = dll_itor->second;
				}
				else
				{
					apis = new rebuildiat_apis;
					dlls.insert_or_assign(dllname, apis);
				}

				bool bInserted = false;
				for (size_t t = 0; t < apis->apis.size(); ++t)
				{
					if (apis->apis[t].funcname == api_ptr->ProcedureName)
					{
						if (m_LastFakeAPICallReturnAddress == 0)
						{
							apis->apis[t].rva48FF25.emplace(vmpcalls[j].insn_rva);
						}
						else if (m_LastFakeAPICallReturnAddress == call_ret + 1)
						{
							apis->apis[t].rvaVMPCallINT3.emplace(vmpcalls[j].insn_rva);
						}
						else
						{
							int retaddr_rva = (int)(m_LastFakeAPICallReturnAddress - m_ImageBase);
							apis->apis[t].rvaVMPCall.emplace_back(vmpcalls[j].insn_rva, retaddr_rva);
						}
						bInserted = true;
						break;
					}
				}

				if (!bInserted)
				{
					rebuildiat_api api;
					api.funcname = api_ptr->ProcedureName;
					if (m_LastFakeAPICallReturnAddress == 0)
					{
						api.rva48FF25.emplace(vmpcalls[j].insn_rva);
					}
					if (m_LastFakeAPICallReturnAddress == call_ret + 1)
					{
						api.rvaVMPCallINT3.emplace(vmpcalls[j].insn_rva);
					}
					else
					{
						int retaddr_rva = (int)(m_LastFakeAPICallReturnAddress - m_ImageBase);
						api.rvaVMPCall.emplace_back(vmpcalls[j].insn_rva, retaddr_rva);
					}
					apis->apis.emplace_back(api);
				}

				*outs << "found VMPCALL IAT 0x" << std::hex << vmpcalls[j].insn_rva << " to " << api_ptr->ProcedureName << "\n";

				if (j < vmpcalls.size() - 1 && vmpcalls[j].insn_rva + 1 == vmpcalls[j + 1].insn_rva)
				{
					j++;
				}
			}
		}
	}

	m_FakeAPICallEnabled = false;

	//estimate the size of rebuilt IAT
	for (auto itor = dlls.begin(); itor != dlls.end(); ++itor)
	{
		auto apis = itor->second;
		for (size_t t = 0; t < apis->apis.size(); ++t)
		{
			if (!apis->apis[t].funcname.empty())
			{
				RebuildSize += apis->apis[t].funcname.length() + 1 + sizeof(WORD);
			}
		}
		RebuildSize += itor->first.length() + 1;
	}
	//align to 8
	//RebuildSize = (AlignSize(RebuildSize, sizeof(ULONG_PTR)));
	for (auto itor = dlls.begin(); itor != dlls.end(); ++itor)
	{
		auto apis = itor->second;
		RebuildSize += sizeof(IMAGE_THUNK_DATA) * (apis->apis.size() + 1) * 2;
	}
	//last member of IMAGE_IMPORT_DESCRIPTOR is filled with all zero
	RebuildSize += sizeof(IMAGE_IMPORT_DESCRIPTOR) * (dlls.size() + 1);
	
	for (size_t j = 0; j < vmpstrs.size(); ++j)
	{
		RebuildSize += vmpstrs[j].bytes.size();
	}

	for (auto itor = dlls.begin(); itor != dlls.end(); ++itor)
	{
		auto apis = itor->second;
		for (size_t t = 0; t < apis->apis.size(); ++t)
		{
			RebuildSize += apis->apis[t].rvaVMPCall.size() * (6 + 5);
		}
	}

	RebuildSize = AlignSize(RebuildSize, ntheader->OptionalHeader.SectionAlignment);
	RebuildIATDescSize = sizeof(IMAGE_IMPORT_DESCRIPTOR) * dlls.size();

	auto iat_ptr = (PUCHAR)RebuildSectionBuffer.GetSpace(RebuildSize);
	memset(iat_ptr, 0, RebuildSize);

	//write new IAT
	PUCHAR current_ptr = iat_ptr;
	for (auto itor = dlls.begin(); itor != dlls.end(); ++itor)
	{
		auto apis = itor->second;
		memcpy(current_ptr, itor->first.c_str(), itor->first.length() + 1);
		apis->dllname_rva = (int)(current_ptr - iat_ptr) + NewIATRva;
		current_ptr += itor->first.length() + 1;

		for (size_t t = 0; t < apis->apis.size(); ++t)
		{
			if (!apis->apis[t].funcname.empty())
			{
				WORD Hint = 0;
				memcpy(current_ptr + 0, &Hint, sizeof(Hint));
				memcpy(current_ptr + offsetof(IMAGE_IMPORT_BY_NAME, Name), apis->apis[t].funcname.c_str(), apis->apis[t].funcname.length() + 1);
				apis->apis[t].funcname_rva = (int)(current_ptr - iat_ptr) + NewIATRva;
				current_ptr += apis->apis[t].funcname.length() + 1 + sizeof(WORD);
			}
		}

		//align to 8
		//current_ptr = (PUCHAR)(AlignSize((ULONG_PTR)current_ptr, sizeof(ULONG_PTR)));

		auto pthunk = (PIMAGE_THUNK_DATA)current_ptr;
		auto pthunk2 = (PIMAGE_THUNK_DATA)current_ptr + (apis->apis.size() + 1);

		for (size_t t = 0; t < apis->apis.size() + 1; ++t)
		{
			if (t == apis->apis.size())
			{
				pthunk[t].u1.AddressOfData = 0;
				pthunk2[t].u1.AddressOfData = 0;
			}
			else if (apis->apis[t].funcname.empty())
			{
				pthunk[t].u1.Ordinal = apis->apis[t].ord;
				pthunk2[t].u1.Ordinal = apis->apis[t].ord;
			}
			else
			{
				pthunk[t].u1.Function = apis->apis[t].funcname_rva;
				pthunk2[t].u1.Function = apis->apis[t].funcname_rva;
			}

			apis->apis[t].iat_rva = (int)((PUCHAR)&pthunk2[t].u1.AddressOfData - iat_ptr) + NewIATRva;
			//rebase the oprand rva of FF15/FF25 insns
			if (t < apis->apis.size())
			{
				for (auto insn_rva : apis->apis[t].rvaFF15)
				{
					int call_rva = apis->apis[t].iat_rva - (insn_rva + 6);
					*(int *)((PUCHAR)ImageBase + insn_rva) = call_rva;
				}
				for (auto insn_rva : apis->apis[t].rvaVMPCallINT3)
				{
					if (insn_rva == 0x1334d)
						__debugbreak();
					*(unsigned char *)((PUCHAR)ImageBase + insn_rva) = 0xFF;
					*(unsigned char *)((PUCHAR)ImageBase + insn_rva + 1) = 0x15;
					int call_rva = apis->apis[t].iat_rva - (insn_rva + 6);
					*(int *)((PUCHAR)ImageBase + insn_rva + 2) = call_rva;
				}
				for (auto insn_rva : apis->apis[t].rva48FF25)
				{
					*(unsigned char *)((PUCHAR)ImageBase + insn_rva) = 0x48;
					*(unsigned char *)((PUCHAR)ImageBase + insn_rva + 1) = 0xFF;
					*(unsigned char *)((PUCHAR)ImageBase + insn_rva + 2) = 0x25;
					int call_rva = apis->apis[t].iat_rva - (insn_rva + 7);
					*(int *)((PUCHAR)ImageBase + insn_rva + 3) = call_rva;
				}
			}
		}

		apis->othunk_rva = (int)(current_ptr - iat_ptr) + NewIATRva;
		apis->thunk_rva = (int)((PUCHAR)pthunk2 - iat_ptr) + NewIATRva;
		current_ptr += sizeof(IMAGE_THUNK_DATA) * (apis->apis.size() + 1) * 2;
	}

	RebuildIATRva = (int)(current_ptr - iat_ptr) + NewIATRva;

	for (auto itor = dlls.begin(); itor != dlls.end(); ++itor)
	{
		auto apis = itor->second;
		auto pdesc = (PIMAGE_IMPORT_DESCRIPTOR)current_ptr;
		pdesc->OriginalFirstThunk = apis->othunk_rva;
		pdesc->FirstThunk = apis->thunk_rva;
		pdesc->Name = apis->dllname_rva;
		current_ptr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
	//reserve an empty one
	current_ptr += sizeof(IMAGE_IMPORT_DESCRIPTOR);

	/*for (size_t j = 0; j < vmpstrs.size(); ++j)
	{
		memcpy(current_ptr, vmpstrs[j].bytes.data(), vmpstrs[j].bytes.size());

		char vmp_str_sig[] = "\x48\x8D\x05\x00\x00\x00\x00\x90\x90\x90\x90\x90\x90";
		int str_rva = (int)(current_ptr - iat_ptr) + NewIATRva - (vmpstrs[j].insn_rva + 7);
		*(int *)(vmp_str_sig + 3) = str_rva;
		memcpy((PUCHAR)ImageBase + vmpstrs[j].insn_rva, vmp_str_sig, sizeof(vmp_str_sig) - 1);
		
		current_ptr += vmpstrs[j].bytes.size();
	}*/

	for (auto itor = dlls.begin(); itor != dlls.end(); ++itor)
	{
		auto apis = itor->second;
		for (size_t t = 0; t < apis->apis.size(); ++t)
		{
			for (auto vmpcall : apis->apis[t].rvaVMPCall)
			{
				if (vmpcall.target_rva == vmpcall.insn_rva + 5)
				{
					//E8 call + FF25 jmp
					char jmp_sig[] = "\xFF\x25\x00\x00\x00\x00\xCC\xCC\xCC\xCC\xCC";
					int jmp_rva = apis->apis[t].iat_rva - NewIATRva - (int)(current_ptr + 6 - iat_ptr);
					*(int *)(jmp_sig + 2) = jmp_rva;
					memcpy(current_ptr, jmp_sig, 11);

					int call_rva = (int)(current_ptr - iat_ptr) + NewIATRva - (vmpcall.insn_rva + 5);
					*(int *)((PUCHAR)ImageBase + vmpcall.insn_rva + 1) = call_rva;

					current_ptr += 11;
				}
				else
				{
					//E9 jmp + FF15 call + E9 jmp back
					/*char jmp_sig[] = "\xFF\x15\x00\x00\x00\x00\xE9\x00\x00\x00\x00";
					int jmp_rva = apis->apis[t].iat_rva - ((int)(current_ptr - iat_ptr + 6) + NewIATRva);
					*(int *)(jmp_sig + 2) = jmp_rva;

					int jmpback_rva = vmpcall.target_rva - ((int)(current_ptr - iat_ptr + 11) + NewIATRva);
					*(int *)(jmp_sig + 7) = jmpback_rva;
					memcpy(current_ptr, jmp_sig, 11);

					int call_rva = (int)(current_ptr - iat_ptr) + NewIATRva - (vmpcall.insn_rva + 5);
					char jmp_sig2[] = "\xE9\x00\x00\x00\x00";
					*(int *)(jmp_sig2 + 1) = call_rva;
					memcpy((PUCHAR)ImageBase + vmpcall.insn_rva, jmp_sig2, 5);

					current_ptr += 11;*/
				}
			}			
		}
	}

	memset(&SectionHeader[SectionCount], 0, sizeof(IMAGE_SECTION_HEADER));
	SectionHeader[SectionCount].VirtualAddress = SectionHeader[SectionCount].PointerToRawData = NewIATRva;
	SectionHeader[SectionCount].SizeOfRawData = (DWORD)RebuildSize;
	SectionHeader[SectionCount].Misc.VirtualSize = RebuildSize;
	SectionHeader[SectionCount].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
	memcpy(SectionHeader[SectionCount].Name, ".ucpe\0\0\0", 8);
	ntheader->FileHeader.NumberOfSections++;

	ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = RebuildIATRva;
	ntheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (DWORD)RebuildIATDescSize;
	ntheader->OptionalHeader.SizeOfImage += (DWORD)RebuildSize;
	ntheader->OptionalHeader.ImageBase = 0x140000000ull;

	return true;
}