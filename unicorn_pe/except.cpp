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

extern "C"
{
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

VOID PeEmulation::RtlInsertInvertedFunctionTable(
	PINVERTED_FUNCTION_TABLE InvertedTable,
	ULONG64 MappedBase,
	PVOID ImageBase,
	ULONG SizeOfImage
){

	ULONG CurrentSize;
	PVOID FunctionTable;
	ULONG Index;
	ULONG SizeOfTable;

	//
	// If the inverted table is not full, then insert the entry in the
	// specified inverted table.
	//

	CurrentSize = InvertedTable->CurrentSize;
	if (CurrentSize != InvertedTable->MaximumSize) {

		//
		// If the inverted table has no entries, then insert the new entry as
		// the first entry. Otherwise, search the inverted table for the proper
		// insert position, shuffle the table, and insert the new entry.
		//

		Index = 0;
		if (CurrentSize != 0) {
			for (Index = 0; Index < CurrentSize; Index += 1) {
				if (ImageBase < InvertedTable->TableEntry[Index].ImageBase) {
					break;
				}
			}

			//
			// If the new entry does not go at the end of the specified table,
			// then shuffle the table down to make room for the new entry.
			//

			if (Index != CurrentSize) {
				RtlMoveMemory(&InvertedTable->TableEntry[Index + 1],
					&InvertedTable->TableEntry[Index],
					(CurrentSize - Index) * sizeof(INVERTED_FUNCTION_TABLE_ENTRY));
			}
		}

		//
		// Insert the specified entry in the specified inverted function table.
		//

		FunctionTable = RtlImageDirectoryEntryToData(ImageBase,
			TRUE,
			IMAGE_DIRECTORY_ENTRY_EXCEPTION,
			&SizeOfTable);

		InvertedTable->TableEntry[Index].FunctionTable = (PRUNTIME_FUNCTION)(MappedBase + ((PUCHAR)FunctionTable - (PUCHAR)ImageBase));
		InvertedTable->TableEntry[Index].ImageBase = (PVOID)MappedBase;
		InvertedTable->TableEntry[Index].SizeOfImage = SizeOfImage;
		InvertedTable->TableEntry[Index].SizeOfTable = SizeOfTable;
		InvertedTable->CurrentSize += 1;
	}
	else {
		InvertedTable->Overflow = TRUE;
	}

	return;
}

NTSTATUS PeEmulation::RaiseException(IN PEXCEPTION_RECORD ExceptionRecord, IN PCONTEXT ContextRecord, IN BOOLEAN FirstChance)
{
	return STATUS_SUCCESS;
}

VOID PeEmulation::RtlpGetStackLimits(
	OUT PULONG64 LowLimit,
	OUT PULONG64 HighLimit
)
{
	*LowLimit = m_StackBase;
	*HighLimit = m_StackEnd;
}

VOID PeEmulation::RtlpRestoreContext(
     IN PCONTEXT ContextRecord,
     IN PEXCEPTION_RECORD ExceptionRecord OPTIONAL
)
{
	uc_reg_write(m_uc, UC_X86_REG_CS, &ContextRecord->SegCs);
	uc_reg_write(m_uc, UC_X86_REG_DS, &ContextRecord->SegDs);
	uc_reg_write(m_uc, UC_X86_REG_ES, &ContextRecord->SegEs);
	uc_reg_write(m_uc, UC_X86_REG_SS, &ContextRecord->SegSs);
	uc_reg_write(m_uc, UC_X86_REG_FS, &ContextRecord->SegFs);
	uc_reg_write(m_uc, UC_X86_REG_GS, &ContextRecord->SegGs);

	uc_reg_write(m_uc, UC_X86_REG_RAX, &ContextRecord->Rax);
	uc_reg_write(m_uc, UC_X86_REG_RBX, &ContextRecord->Rbx);
	uc_reg_write(m_uc, UC_X86_REG_RCX, &ContextRecord->Rcx);
	uc_reg_write(m_uc, UC_X86_REG_RDX, &ContextRecord->Rdx);
	uc_reg_write(m_uc, UC_X86_REG_RSI, &ContextRecord->Rsi);
	uc_reg_write(m_uc, UC_X86_REG_RDI, &ContextRecord->Rdi);
	uc_reg_write(m_uc, UC_X86_REG_R8, &ContextRecord->R8);
	uc_reg_write(m_uc, UC_X86_REG_R9, &ContextRecord->R9);
	uc_reg_write(m_uc, UC_X86_REG_R10, &ContextRecord->R10);
	uc_reg_write(m_uc, UC_X86_REG_R11, &ContextRecord->R11);
	uc_reg_write(m_uc, UC_X86_REG_R12, &ContextRecord->R12);
	uc_reg_write(m_uc, UC_X86_REG_R13, &ContextRecord->R13);
	uc_reg_write(m_uc, UC_X86_REG_R14, &ContextRecord->R14);
	uc_reg_write(m_uc, UC_X86_REG_R15, &ContextRecord->R15);
	uc_reg_write(m_uc, UC_X86_REG_RBP, &ContextRecord->Rbp);

	uc_reg_write(m_uc, UC_X86_REG_XMM0, &ContextRecord->Xmm0);
	uc_reg_write(m_uc, UC_X86_REG_XMM1, &ContextRecord->Xmm1);
	uc_reg_write(m_uc, UC_X86_REG_XMM2, &ContextRecord->Xmm2);
	uc_reg_write(m_uc, UC_X86_REG_XMM3, &ContextRecord->Xmm3);
	uc_reg_write(m_uc, UC_X86_REG_XMM4, &ContextRecord->Xmm4);
	uc_reg_write(m_uc, UC_X86_REG_XMM5, &ContextRecord->Xmm5);
	uc_reg_write(m_uc, UC_X86_REG_XMM6, &ContextRecord->Xmm6);
	uc_reg_write(m_uc, UC_X86_REG_XMM7, &ContextRecord->Xmm7);
	uc_reg_write(m_uc, UC_X86_REG_XMM8, &ContextRecord->Xmm8);
	uc_reg_write(m_uc, UC_X86_REG_XMM9, &ContextRecord->Xmm9);
	uc_reg_write(m_uc, UC_X86_REG_XMM10, &ContextRecord->Xmm10);
	uc_reg_write(m_uc, UC_X86_REG_XMM11, &ContextRecord->Xmm11);
	uc_reg_write(m_uc, UC_X86_REG_XMM12, &ContextRecord->Xmm12);
	uc_reg_write(m_uc, UC_X86_REG_XMM13, &ContextRecord->Xmm13);
	uc_reg_write(m_uc, UC_X86_REG_XMM14, &ContextRecord->Xmm14);
	uc_reg_write(m_uc, UC_X86_REG_XMM15, &ContextRecord->Xmm15);

	uc_reg_write(m_uc, UC_X86_REG_EFLAGS, &ContextRecord->EFlags);
	uc_reg_write(m_uc, UC_X86_REG_RSP, &ContextRecord->Rsp);
	uc_reg_write(m_uc, UC_X86_REG_RIP, &ContextRecord->Rip);
	m_ExecuteFromRip = ContextRecord->Rip;

	uc_reg_write(m_uc, UC_X86_REG_DR0, &ContextRecord->Dr0);
	uc_reg_write(m_uc, UC_X86_REG_DR1, &ContextRecord->Dr1);
	uc_reg_write(m_uc, UC_X86_REG_DR2, &ContextRecord->Dr2);
	uc_reg_write(m_uc, UC_X86_REG_DR3, &ContextRecord->Dr3);
	uc_reg_write(m_uc, UC_X86_REG_DR6, &ContextRecord->Dr6);
	uc_reg_write(m_uc, UC_X86_REG_DR7, &ContextRecord->Dr7);
}

VOID PeEmulation::RtlpCaptureContext(IN PCONTEXT ContextRecord)
{	
	uc_reg_read(m_uc, UC_X86_REG_CS, &ContextRecord->SegCs);
	uc_reg_read(m_uc, UC_X86_REG_DS, &ContextRecord->SegDs);
	uc_reg_read(m_uc, UC_X86_REG_ES, &ContextRecord->SegEs);
	uc_reg_read(m_uc, UC_X86_REG_SS, &ContextRecord->SegSs);
	uc_reg_read(m_uc, UC_X86_REG_FS, &ContextRecord->SegFs);
	uc_reg_read(m_uc, UC_X86_REG_GS, &ContextRecord->SegGs);

	uc_reg_read(m_uc, UC_X86_REG_RAX, &ContextRecord->Rax);
	uc_reg_read(m_uc, UC_X86_REG_RBX, &ContextRecord->Rbx);
	uc_reg_read(m_uc, UC_X86_REG_RCX, &ContextRecord->Rcx);
	uc_reg_read(m_uc, UC_X86_REG_RDX, &ContextRecord->Rdx);
	uc_reg_read(m_uc, UC_X86_REG_RSI, &ContextRecord->Rsi);
	uc_reg_read(m_uc, UC_X86_REG_RDI, &ContextRecord->Rdi);
	uc_reg_read(m_uc, UC_X86_REG_R8, &ContextRecord->R8);
	uc_reg_read(m_uc, UC_X86_REG_R9, &ContextRecord->R9);
	uc_reg_read(m_uc, UC_X86_REG_R10, &ContextRecord->R10);
	uc_reg_read(m_uc, UC_X86_REG_R11, &ContextRecord->R11);
	uc_reg_read(m_uc, UC_X86_REG_R12, &ContextRecord->R12);
	uc_reg_read(m_uc, UC_X86_REG_R13, &ContextRecord->R13);
	uc_reg_read(m_uc, UC_X86_REG_R14, &ContextRecord->R14);
	uc_reg_read(m_uc, UC_X86_REG_R15, &ContextRecord->R15);
	uc_reg_read(m_uc, UC_X86_REG_RBP, &ContextRecord->Rbp);

	uc_reg_read(m_uc, UC_X86_REG_XMM0, &ContextRecord->Xmm0);
	uc_reg_read(m_uc, UC_X86_REG_XMM1, &ContextRecord->Xmm1);
	uc_reg_read(m_uc, UC_X86_REG_XMM2, &ContextRecord->Xmm2);
	uc_reg_read(m_uc, UC_X86_REG_XMM3, &ContextRecord->Xmm3);
	uc_reg_read(m_uc, UC_X86_REG_XMM4, &ContextRecord->Xmm4);
	uc_reg_read(m_uc, UC_X86_REG_XMM5, &ContextRecord->Xmm5);
	uc_reg_read(m_uc, UC_X86_REG_XMM6, &ContextRecord->Xmm6);
	uc_reg_read(m_uc, UC_X86_REG_XMM7, &ContextRecord->Xmm7);
	uc_reg_read(m_uc, UC_X86_REG_XMM8, &ContextRecord->Xmm8);
	uc_reg_read(m_uc, UC_X86_REG_XMM9, &ContextRecord->Xmm9);
	uc_reg_read(m_uc, UC_X86_REG_XMM10, &ContextRecord->Xmm10);
	uc_reg_read(m_uc, UC_X86_REG_XMM11, &ContextRecord->Xmm11);
	uc_reg_read(m_uc, UC_X86_REG_XMM12, &ContextRecord->Xmm12);
	uc_reg_read(m_uc, UC_X86_REG_XMM13, &ContextRecord->Xmm13);
	uc_reg_read(m_uc, UC_X86_REG_XMM14, &ContextRecord->Xmm14);
	uc_reg_read(m_uc, UC_X86_REG_XMM15, &ContextRecord->Xmm15);

	uc_reg_read(m_uc, UC_X86_REG_RIP, &ContextRecord->Rip);
	uc_reg_read(m_uc, UC_X86_REG_RSP, &ContextRecord->Rsp);
	uc_reg_read(m_uc, UC_X86_REG_EFLAGS, &ContextRecord->EFlags);

	uc_reg_read(m_uc, UC_X86_REG_DR0, &ContextRecord->Dr0);
	uc_reg_read(m_uc, UC_X86_REG_DR1, &ContextRecord->Dr1);
	uc_reg_read(m_uc, UC_X86_REG_DR2, &ContextRecord->Dr2);
	uc_reg_read(m_uc, UC_X86_REG_DR3, &ContextRecord->Dr3);
	uc_reg_read(m_uc, UC_X86_REG_DR6, &ContextRecord->Dr6);
	uc_reg_read(m_uc, UC_X86_REG_DR7, &ContextRecord->Dr7);

	ContextRecord->ContextFlags = CONTEXT_FULL;
}

VOID
RtlpCopyContext(
	OUT PCONTEXT Destination,
	IN PCONTEXT Source
){

	//
	// Copy nonvolatile context required for exception dispatch and unwind.
	//

	Destination->Rip = Source->Rip;
	Destination->Rbx = Source->Rbx;
	Destination->Rsp = Source->Rsp;
	Destination->Rbp = Source->Rbp;
	Destination->Rsi = Source->Rsi;
	Destination->Rdi = Source->Rdi;
	Destination->R12 = Source->R12;
	Destination->R13 = Source->R13;
	Destination->R14 = Source->R14;
	Destination->R15 = Source->R15;
	Destination->Xmm6 = Source->Xmm6;
	Destination->Xmm7 = Source->Xmm7;
	Destination->Xmm8 = Source->Xmm8;
	Destination->Xmm9 = Source->Xmm9;
	Destination->Xmm10 = Source->Xmm10;
	Destination->Xmm11 = Source->Xmm11;
	Destination->Xmm12 = Source->Xmm12;
	Destination->Xmm13 = Source->Xmm13;
	Destination->Xmm14 = Source->Xmm14;
	Destination->Xmm15 = Source->Xmm15;
	Destination->SegCs = Source->SegCs;
	Destination->SegSs = Source->SegSs;
	Destination->MxCsr = Source->MxCsr;
	Destination->EFlags = Source->EFlags;

	return;
}

BOOLEAN
RtlpIsFrameInBounds(
	IN OUT PULONG64 LowLimit,
	IN ULONG64 StackFrame,
	IN OUT PULONG64 HighLimit
)
{
	if ((StackFrame & 0x7) != 0) {
		return FALSE;
	}

	if ((StackFrame < *LowLimit) ||
		(StackFrame >= *HighLimit)) {

		return FALSE;

	}
	else {
		return TRUE;
	}
}

VOID PeEmulation::RtlRaiseStatus(IN NTSTATUS Status)
{
	CONTEXT ContextRecord;
	EXCEPTION_RECORD ExceptionRecord;

	//
	// Capture the current context and construct an exception record.
	//

	RtlpCaptureContext(&ContextRecord);
	ExceptionRecord.ExceptionCode = Status;
	ExceptionRecord.ExceptionRecord = NULL;
	ExceptionRecord.NumberParameters = 0;
	ExceptionRecord.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
	ExceptionRecord.ExceptionAddress = (PVOID)ContextRecord.Rip;

	//
	// Attempt to dispatch the exception.
	//
	// N.B. This exception is non-continuable.
	//

	RtlpDispatchException(&ExceptionRecord, &ContextRecord);
	Status = RaiseException(&ExceptionRecord, &ContextRecord, FALSE);
}

PRUNTIME_FUNCTION
RtlpSearchInvertedFunctionTable(
	PINVERTED_FUNCTION_TABLE InvertedTable,
	PVOID ControlPc,
	OUT PVOID *ImageBase,
	OUT PULONG SizeOfTable
)

/*++

Routine Description:

	This function searches for a matching entry in an inverted function
	table using the specified control PC value.

	N.B. It is assumed that appropriate locks are held when this routine
		 is called.

Arguments:

	InvertedTable - Supplies a pointer to an inverted function table.

	ControlPc - Supplies a PC value to to use in searching the inverted
		function table.

	ImageBase - Supplies a pointer to a variable that receives the base
		 address of the corresponding module.

	SizeOfTable - Supplies a pointer to a variable that receives the size
		 of the function table in bytes.

Return Value:

	If a matching entry is located in the specified function table, then
	the function table address is returned as the function value. Otherwise,
	a value of NULL is returned.

--*/

{

	PVOID Bound;
	LONG High;
	ULONG Index;
	PINVERTED_FUNCTION_TABLE_ENTRY InvertedEntry;
	LONG Low;
	LONG Middle;

	//
	// If there are any entries in the specified inverted function table,
	// then search the table for a matching entry.
	//

	if (InvertedTable->CurrentSize != 0) {
		Low = 0;
		High = InvertedTable->CurrentSize - 1;
		while (High >= Low) {

			//
			// Compute next probe index and test entry. If the specified
			// control PC is greater than of equal to the beginning address
			// and less than the ending address of the inverted function
			// table entry, then return the address of the function table.
			// Otherwise, continue the search.
			//

			Middle = (Low + High) >> 1;
			InvertedEntry = &InvertedTable->TableEntry[Middle];
			Bound = (PVOID)((ULONG_PTR)InvertedEntry->ImageBase + InvertedEntry->SizeOfImage);
			if (ControlPc < InvertedEntry->ImageBase) {
				High = Middle - 1;

			}
			else if (ControlPc >= Bound) {
				Low = Middle + 1;

			}
			else {
				*ImageBase = InvertedEntry->ImageBase;
				*SizeOfTable = InvertedEntry->SizeOfTable;
				return InvertedEntry->FunctionTable;
			}
		}
	}

	return NULL;
}

PRUNTIME_FUNCTION PeEmulation::RtlpLookupFunctionTable(
	IN PVOID ControlPc,
	OUT PVOID *ImageBase,
	OUT PULONG SizeOfTable
)
{
	PVOID Base;
	ULONG_PTR Bound;

	PKLDR_DATA_TABLE_ENTRY Entry;

	PLIST_ENTRY Next;

	PRUNTIME_FUNCTION FunctionTable;

	FunctionTable = RtlpSearchInvertedFunctionTable(&m_PsInvertedFunctionTable,
		ControlPc,
		&Base,
		SizeOfTable);

	if ((FunctionTable == NULL) &&
		(m_PsInvertedFunctionTable.Overflow != FALSE))

	{
		LIST_ENTRY PsLoadedModuleList;
		uc_mem_read(m_uc, m_PsLoadedModuleListBase, &PsLoadedModuleList, sizeof(PsLoadedModuleList));
		
		Next = PsLoadedModuleList.Flink;
		if (Next != NULL) {
			while (Next != (PLIST_ENTRY)m_PsLoadedModuleListBase) {
				Entry = CONTAINING_RECORD(Next,
					KLDR_DATA_TABLE_ENTRY,
					InLoadOrderLinks);

				uc_mem_read(m_uc, (uint64_t)Entry + offsetof(KLDR_DATA_TABLE_ENTRY, DllBase), &Base, sizeof(Base));
				
				ULONG SizeOfImage;
				uc_mem_read(m_uc, (uint64_t)Entry + offsetof(KLDR_DATA_TABLE_ENTRY, SizeOfImage), &SizeOfImage, sizeof(SizeOfImage));
				
				Bound = (ULONG_PTR)Base + SizeOfImage;
				if (((ULONG_PTR)ControlPc >= (ULONG_PTR)Base) &&
					((ULONG_PTR)ControlPc < Bound)) {
					
					ULONG sizeOfTable;
					uc_mem_read(m_uc, (uint64_t)Entry + offsetof(KLDR_DATA_TABLE_ENTRY, ExceptionTable), &FunctionTable, sizeof(FunctionTable));
					uc_mem_read(m_uc, (uint64_t)Entry + offsetof(KLDR_DATA_TABLE_ENTRY, ExceptionTableSize), &sizeOfTable, sizeof(sizeOfTable));

					*SizeOfTable = sizeOfTable;
					break;
				}

				PLIST_ENTRY ptrFlink;
				uc_mem_read(m_uc, (uint64_t)Next + offsetof(LIST_ENTRY, Flink), &ptrFlink, sizeof(ptrFlink));
				Next = ptrFlink;
			}
		}
	}

	*ImageBase = Base;
	return FunctionTable;
}

PRUNTIME_FUNCTION
PeEmulation::RtlpConvertFunctionEntry(
	IN PRUNTIME_FUNCTION FunctionEntry,
	IN ULONG64 ImageBase
)
{

	//
	// If the specified function entry is not NULL and specifies indirection,
	// then compute the address of the master function table entry.
	//

	if (FunctionEntry) {
		RUNTIME_FUNCTION FunctionEntryCell;
		uc_mem_read(m_uc, (uint64_t)FunctionEntry, &FunctionEntryCell, sizeof(FunctionEntryCell));
		
		if ((FunctionEntryCell.UnwindData & RUNTIME_FUNCTION_INDIRECT) != 0) {
			FunctionEntry = (PRUNTIME_FUNCTION)(FunctionEntryCell.UnwindData + ImageBase - 1);
		}
	}

	return FunctionEntry;
}

PRUNTIME_FUNCTION PeEmulation::RtlpLookupFunctionEntry(
	IN ULONG64 ControlPc,
	OUT PULONG64 ImageBase,
	IN OUT PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL
)
{

	ULONG64 BaseAddress;
	ULONG64 BeginAddress;
	ULONG64 EndAddress;
	PRUNTIME_FUNCTION FunctionEntry = NULL;
	PRUNTIME_FUNCTION FunctionTable = NULL;
	LONG High;
	ULONG Index;
	LONG Low;
	LONG Middle;
	ULONG RelativePc;
	ULONG SizeOfTable;

	//
	// Attempt to find an image that contains the specified control PC. If
	// an image is found, then search its function table for a function table
	// entry that contains the specified control PC. If an image is not found
	// then search the dynamic function table for an image that contains the
	// specified control PC.
	//
	// If a history table is supplied and search is specfied, then the current
	// operation that is being performed is the unwind phase of an exception
	// dispatch followed by a unwind. 
	//

	if (HistoryTable &&
		(HistoryTable->Search != UNWIND_HISTORY_TABLE_NONE)) {

		//
		// Search the global unwind history table if there is a chance of a
		// match.
		//
		// N.B. The global unwind history table never contains indirect entries.
		//

		/*if (HistoryTable->Search == UNWIND_HISTORY_TABLE_GLOBAL) {
			if ((ControlPc >= RtlpUnwindHistoryTable.LowAddress) &&
				(ControlPc < RtlpUnwindHistoryTable.HighAddress)) {

				for (Index = 0; Index < RtlpUnwindHistoryTable.Count; Index += 1) {
					BaseAddress = RtlpUnwindHistoryTable.Entry[Index].ImageBase;
					FunctionEntry = RtlpUnwindHistoryTable.Entry[Index].FunctionEntry;
					BeginAddress = FunctionEntry->BeginAddress + BaseAddress;
					EndAddress = FunctionEntry->EndAddress + BaseAddress;
					if ((ControlPc >= BeginAddress) && (ControlPc < EndAddress)) {
						*ImageBase = BaseAddress;
						return FunctionEntry;
					}
				}
			}

			HistoryTable->Search = UNWIND_HISTORY_TABLE_LOCAL;
		}*/

		//
		// Search the dynamic unwind history table if there is a chance of a
		// match.
		//
		// N.B. The dynamic unwind history table can contain indirect entries.
		//

		if ((ControlPc >= HistoryTable->LowAddress) &&
			(ControlPc < HistoryTable->HighAddress)) {

			for (Index = 0; Index < HistoryTable->Count; Index += 1) {
				BaseAddress = HistoryTable->Entry[Index].ImageBase;
				FunctionEntry = HistoryTable->Entry[Index].FunctionEntry;

				RUNTIME_FUNCTION FunctionEntryCell;
				uc_mem_read(m_uc, (uint64_t)FunctionEntry, &FunctionEntryCell, sizeof(FunctionEntryCell));

				BeginAddress = FunctionEntryCell.BeginAddress + BaseAddress;
				EndAddress = FunctionEntryCell.EndAddress + BaseAddress;
				if ((ControlPc >= BeginAddress) && (ControlPc < EndAddress)) {
					*ImageBase = BaseAddress;
					return RtlpConvertFunctionEntry(FunctionEntry, *ImageBase);
				}
			}
		}
	}

	//
	// There was not a match in either of the unwind history tables so attempt
	// to find a matching entry in the loaded module list.
	//

	FunctionTable = RtlpLookupFunctionTable((PVOID)ControlPc,
		(PVOID *)ImageBase,
		&SizeOfTable);

	//
	// If a function table is located, then search for a function table
	// entry that contains the specified control PC.
	//

	if (FunctionTable != NULL) {
		Low = 0;
		High = (SizeOfTable / sizeof(RUNTIME_FUNCTION)) - 1;
		RelativePc = (ULONG)(ControlPc - *ImageBase);
		while (High >= Low) {

			//
			// Compute next probe index and test entry. If the specified
			// control PC is greater than of equal to the beginning address
			// and less than the ending address of the function table entry,
			// then return the address of the function table entry. Otherwise,
			// continue the search.
			//

			Middle = (Low + High) >> 1;
			FunctionEntry = &FunctionTable[Middle];

			RUNTIME_FUNCTION FunctionEntryCell;
			uc_mem_read(m_uc, (uint64_t)FunctionEntry, &FunctionEntryCell, sizeof(FunctionEntryCell));

			if (RelativePc < FunctionEntryCell.BeginAddress) {
				High = Middle - 1;

			}
			else if (RelativePc >= FunctionEntryCell.EndAddress) {
				Low = Middle + 1;
			}
			else {
				break;
			}
		}

		if (High < Low) {
			FunctionEntry = NULL;
		}

	}
	else {

		//
		// There was not a match in the loaded module list so attempt to find
		// a matching entry in the dynamic function table list.
		//

		FunctionEntry = NULL;
	}

	//
	// If a function table entry was located, search is not specified, and
	// the specfied history table is not full, then attempt to make an entry
	// in the history table.
	//

	if (FunctionEntry != NULL) {
		if (HistoryTable &&
			(HistoryTable->Search == UNWIND_HISTORY_TABLE_NONE) &&
			(HistoryTable->Count < UNWIND_HISTORY_TABLE_SIZE)) {

			Index = HistoryTable->Count;
			HistoryTable->Count += 1;
			HistoryTable->Entry[Index].ImageBase = *ImageBase;
			HistoryTable->Entry[Index].FunctionEntry = FunctionEntry;
			RUNTIME_FUNCTION FunctionEntryCell;
			uc_mem_read(m_uc, (uint64_t)FunctionEntry, &FunctionEntryCell, sizeof(FunctionEntryCell));
			BeginAddress = FunctionEntryCell.BeginAddress + *ImageBase;
			EndAddress = FunctionEntryCell.EndAddress + *ImageBase;
			if (BeginAddress < HistoryTable->LowAddress) {
				HistoryTable->LowAddress = BeginAddress;

			}

			if (EndAddress > HistoryTable->HighAddress) {
				HistoryTable->HighAddress = EndAddress;
			}
		}
	}

	return RtlpConvertFunctionEntry(FunctionEntry, *ImageBase);
}

PUNWIND_INFO PeEmulation::RtlpLookupPrimaryUnwindInfo(
	IN PRUNTIME_FUNCTION FunctionEntry,
	IN ULONG64 ImageBase,
	OUT PRUNTIME_FUNCTION *PrimaryEntry
)
{

	ULONG Index;
	PUNWIND_INFO UnwindInfo;
	RUNTIME_FUNCTION FunctionEntryCell;
	uc_mem_read(m_uc, (uint64_t)FunctionEntry, &FunctionEntryCell, sizeof(FunctionEntryCell));

	//
	// Locate the unwind information and determine whether it is chained.
	// If the unwind information is chained, then locate the parent function
	// entry and loop again.
	//

	do {
		UnwindInfo = (PUNWIND_INFO)(FunctionEntryCell.UnwindData + ImageBase);

		crt_buffer_t UnwindInfoCell(offsetof(UNWIND_INFO, UnwindCode));
		uc_mem_read(m_uc, (uint64_t)UnwindInfo, UnwindInfoCell.GetBuffer(), UnwindInfoCell.GetLength());
		PUNWIND_INFO UnwindInfoCellPtr = (PUNWIND_INFO)UnwindInfoCell.GetBuffer();
		UnwindInfoCell.GetSpace(offsetof(UNWIND_INFO, UnwindCode) + UnwindInfoCellPtr->CountOfCodes * sizeof(UNWIND_CODE));
		uc_mem_read(m_uc, (uint64_t)UnwindInfo, UnwindInfoCell.GetBuffer(), UnwindInfoCell.GetLength());
		UnwindInfoCellPtr = (PUNWIND_INFO)UnwindInfoCell.GetBuffer();

		if ((UnwindInfoCellPtr->Flags & UNW_FLAG_CHAININFO) == 0) {
			break;
		}

		Index = UnwindInfoCellPtr->CountOfCodes;
		if ((Index & 1) != 0) {
			Index += 1;
		}

		FunctionEntry = (PRUNTIME_FUNCTION)&UnwindInfoCellPtr->UnwindCode[Index];
	} while (TRUE);

	*PrimaryEntry = FunctionEntry;
	return UnwindInfo;
}

PRUNTIME_FUNCTION PeEmulation::RtlpSameFunction(
	IN PRUNTIME_FUNCTION FunctionEntry,
	IN ULONG64 ImageBase,
	IN ULONG64 ControlPc
)
{

	PRUNTIME_FUNCTION PrimaryFunctionEntry;
	PRUNTIME_FUNCTION TargetFunctionEntry;
	ULONG64 TargetImageBase;
	PUNWIND_INFO UnwindInfo1;
	PUNWIND_INFO UnwindInfo2;

	//
	// Lookup the primary function entry associated with the specified
	// function entry.
	// 

	UnwindInfo1 = RtlpLookupPrimaryUnwindInfo(FunctionEntry,
		ImageBase,
		&PrimaryFunctionEntry);

	//
	// Determine the function entry containing the control Pc and similarly
	// resolve its primary function entry.  If no function entry can be
	// found then the control pc resides in a different function.
	//

	TargetFunctionEntry = RtlpLookupFunctionEntry(ControlPc,
		&TargetImageBase,
		NULL);

	if (TargetFunctionEntry == NULL) {
		return NULL;
	}

	//
	// Lookup the primary function entry associated with the target function
	// entry.
	//

	UnwindInfo2 = RtlpLookupPrimaryUnwindInfo(TargetFunctionEntry,
		TargetImageBase,
		&PrimaryFunctionEntry);

	//
	// If the address of the two sets of unwind information are equal, then
	// return the address of the primary function entry. Otherwise, return
	// NULL.
	//

	if (UnwindInfo1 == UnwindInfo2) {
		return PrimaryFunctionEntry;

	}
	else {
		return NULL;
	}
}

PRUNTIME_FUNCTION PeEmulation::RtlpUnwindPrologue(
	IN ULONG64 ImageBase,
	IN ULONG64 ControlPc,
	IN ULONG64 FrameBase,
	IN PRUNTIME_FUNCTION FunctionEntry,
	IN OUT PCONTEXT ContextRecord,
	IN OUT PKNONVOLATILE_CONTEXT_POINTERS ContextPointers OPTIONAL
)
{

	PM128A FloatingAddress;
	PM128A FloatingRegister;
	ULONG FrameOffset;
	ULONG Index;
	PULONG64 IntegerAddress;
	PULONG64 IntegerRegister;
	BOOLEAN MachineFrame;
	ULONG OpInfo;
	ULONG PrologOffset;
	PULONG64 RegisterAddress;
	PULONG64 ReturnAddress;
	PULONG64 StackAddress;
	PUNWIND_CODE UnwindCode;
	PUNWIND_INFO UnwindInfo;
	ULONG UnwindOp;
	uint64_t ValueFromAddress;

	//
	// Process the unwind codes.
	//

	FloatingRegister = &ContextRecord->Xmm0;
	IntegerRegister = &ContextRecord->Rax;
	Index = 0;
	MachineFrame = FALSE;

	RUNTIME_FUNCTION FunctionEntryCell;
	uc_mem_read(m_uc, (uint64_t)FunctionEntry, &FunctionEntryCell, sizeof(FunctionEntryCell));

	PrologOffset = (ULONG)(ControlPc - (FunctionEntryCell.BeginAddress + ImageBase));
	UnwindInfo = (PUNWIND_INFO)(FunctionEntryCell.UnwindData + ImageBase);

	crt_buffer_t UnwindInfoCell(offsetof(UNWIND_INFO, UnwindCode));
	uc_mem_read(m_uc, (uint64_t)UnwindInfo, UnwindInfoCell.GetBuffer(), UnwindInfoCell.GetLength());
	PUNWIND_INFO UnwindInfoCellPtr = (PUNWIND_INFO)UnwindInfoCell.GetBuffer();
	UnwindInfoCell.GetSpace(offsetof(UNWIND_INFO, UnwindCode) + UnwindInfoCellPtr->CountOfCodes * sizeof(UNWIND_CODE) + sizeof(DWORD) * 2);
	uc_mem_read(m_uc, (uint64_t)UnwindInfo, UnwindInfoCell.GetBuffer(), UnwindInfoCell.GetLength());
	UnwindInfoCellPtr = (PUNWIND_INFO)UnwindInfoCell.GetBuffer();

	while (Index < UnwindInfoCellPtr->CountOfCodes) {

		//
		// If the prologue offset is greater than the next unwind code offset,
		// then simulate the effect of the unwind code.
		//

		UnwindOp = UnwindInfoCellPtr->UnwindCode[Index].UnwindOp;
		OpInfo = UnwindInfoCellPtr->UnwindCode[Index].OpInfo;
		if (PrologOffset >= UnwindInfoCellPtr->UnwindCode[Index].CodeOffset) {
			switch (UnwindOp) {

				//
				// Push nonvolatile integer register.
				//
				// The operation information is the register number of the
				// register than was pushed.
				//

			case UWOP_PUSH_NONVOL:
				IntegerAddress = (PULONG64)(ContextRecord->Rsp);

				uc_mem_read(m_uc, (uint64_t)IntegerAddress, &ValueFromAddress, sizeof(ValueFromAddress));

				IntegerRegister[OpInfo] = ValueFromAddress;
				if (ContextPointers) {
					ContextPointers->IntegerContext[OpInfo] = IntegerAddress;
				}

				ContextRecord->Rsp += 8;
				break;

				//
				// Allocate a large sized area on the stack.
				//
				// The operation information determines if the size is
				// 16- or 32-bits.
				//

			case UWOP_ALLOC_LARGE:
				Index += 1;
				FrameOffset = UnwindInfoCellPtr->UnwindCode[Index].FrameOffset;
				if (OpInfo != 0) {
					Index += 1;
					FrameOffset += (UnwindInfoCellPtr->UnwindCode[Index].FrameOffset << 16);

				}
				else {
					FrameOffset *= 8;
				}

				ContextRecord->Rsp += FrameOffset;
				break;

				//
				// Allocate a small sized area on the stack.
				//
				// The operation information is the size of the unscaled
				// allocation size (8 is the scale factor) minus 8.
				//

			case UWOP_ALLOC_SMALL:
				ContextRecord->Rsp += (OpInfo * 8) + 8;
				break;

				//
				// Establish the the frame pointer register.
				//
				// The operation information is not used.
				//

			case UWOP_SET_FPREG:
				ContextRecord->Rsp = IntegerRegister[UnwindInfoCellPtr->FrameRegister];
				ContextRecord->Rsp -= UnwindInfoCellPtr->FrameOffset * 16;
				break;

				//
				// Save nonvolatile integer register on the stack using a
				// 16-bit displacment.
				//
				// The operation information is the register number.
				//

			case UWOP_SAVE_NONVOL:
				Index += 1;
				FrameOffset = UnwindInfoCellPtr->UnwindCode[Index].FrameOffset * 8;
				IntegerAddress = (PULONG64)(FrameBase + FrameOffset);

				uc_mem_read(m_uc, (uint64_t)IntegerAddress, &ValueFromAddress, sizeof(ValueFromAddress));

				IntegerRegister[OpInfo] = ValueFromAddress;
				if (ContextPointers) {
					ContextPointers->IntegerContext[OpInfo] = IntegerAddress;
				}

				break;

				//
				// Save nonvolatile integer register on the stack using a
				// 32-bit displacment.
				//
				// The operation information is the register number.
				//

			case UWOP_SAVE_NONVOL_FAR:
				Index += 2;
				FrameOffset = UnwindInfoCellPtr->UnwindCode[Index - 1].FrameOffset;
				FrameOffset += (UnwindInfoCellPtr->UnwindCode[Index].FrameOffset << 16);
				IntegerAddress = (PULONG64)(FrameBase + FrameOffset);
				uc_mem_read(m_uc, (uint64_t)IntegerAddress, &ValueFromAddress, sizeof(ValueFromAddress));
				IntegerRegister[OpInfo] = ValueFromAddress;
				if (ContextPointers) {
					ContextPointers->IntegerContext[OpInfo] = IntegerAddress;
				}

				break;

				//
				// Spare unused codes.
				//

			case UWOP_SPARE_CODE1:
			case UWOP_SPARE_CODE2:

				break;

				//
				// Save a nonvolatile XMM(128) register on the stack using a
				// 16-bit displacement.
				//
				// The operation information is the register number.
				//

			case UWOP_SAVE_XMM128:
				Index += 1;
				FrameOffset = UnwindInfoCellPtr->UnwindCode[Index].FrameOffset * 16;
				FloatingAddress = (PM128A)(FrameBase + FrameOffset);
				FloatingRegister[OpInfo].Low = FloatingAddress->Low;
				FloatingRegister[OpInfo].High = FloatingAddress->High;
				if (ContextPointers) {
					ContextPointers->FloatingContext[OpInfo] = FloatingAddress;
				}

				break;

				//
				// Save a nonvolatile XMM(128) register on the stack using a
				// 32-bit displacement.
				//
				// The operation information is the register number.
				//

			case UWOP_SAVE_XMM128_FAR:
				Index += 2;
				FrameOffset = UnwindInfoCellPtr->UnwindCode[Index - 1].FrameOffset;
				FrameOffset += (UnwindInfoCellPtr->UnwindCode[Index].FrameOffset << 16);
				FloatingAddress = (PM128A)(FrameBase + FrameOffset);
				FloatingRegister[OpInfo].Low = FloatingAddress->Low;
				FloatingRegister[OpInfo].High = FloatingAddress->High;
				if (ContextPointers) {
					ContextPointers->FloatingContext[OpInfo] = FloatingAddress;
				}

				break;

				//
				// Push a machine frame on the stack.
				//
				// The operation information determines whether the machine
				// frame contains an error code or not.
				//

			case UWOP_PUSH_MACHFRAME:
				MachineFrame = TRUE;
				ReturnAddress = (PULONG64)(ContextRecord->Rsp);
				StackAddress = (PULONG64)(ContextRecord->Rsp + (3 * 8));
				if (OpInfo != 0) {
					ReturnAddress += 1;
					StackAddress += 1;
				}

				uc_mem_read(m_uc, (uint64_t)ReturnAddress, &ValueFromAddress, sizeof(ValueFromAddress));

				ContextRecord->Rip = ValueFromAddress;

				uc_mem_read(m_uc, (uint64_t)StackAddress, &ValueFromAddress, sizeof(ValueFromAddress));

				ContextRecord->Rsp = ValueFromAddress;
				break;

				//
				// Unused codes.
				//

			default:

				break;
			}

			Index += 1;

		}
		else {

			//
			// Skip this unwind operation by advancing the slot index by the
			// number of slots consumed by this operation.
			//

			Index += m_RtlpUnwindOpSlotTable[UnwindOp];

			//
			// Special case any unwind operations that can consume a variable
			// number of slots.
			// 

			switch (UnwindOp) {

				//
				// A non-zero operation information indicates that an
				// additional slot is consumed.
				//

			case UWOP_ALLOC_LARGE:
				if (OpInfo != 0) {
					Index += 1;
				}

				break;

				//
				// No other special cases.
				//

			default:
				break;
			}
		}
	}

	//
	// If chained unwind information is specified, then recursively unwind
	// the chained information. Otherwise, determine the return address if
	// a machine frame was not encountered during the scan of the unwind
	// codes.
	//

	if ((UnwindInfoCellPtr->Flags & UNW_FLAG_CHAININFO) != 0) {
		Index = UnwindInfoCellPtr->CountOfCodes;
		if ((Index & 1) != 0) {
			Index += 1;
		}

		FunctionEntry = (PRUNTIME_FUNCTION)(&UnwindInfoCellPtr->UnwindCode[Index]);
		return RtlpUnwindPrologue(ImageBase,
			ControlPc,
			FrameBase,
			FunctionEntry,
			ContextRecord,
			ContextPointers);

	}
	else {
		if (MachineFrame == FALSE) {

			uint64_t ValueFromAddress;
			uc_mem_read(m_uc, (uint64_t)ContextRecord->Rsp, &ValueFromAddress, sizeof(ValueFromAddress));

			ContextRecord->Rip = ValueFromAddress;
			ContextRecord->Rsp += 8;
		}

		return FunctionEntry;
	}
}

PEXCEPTION_ROUTINE PeEmulation::RtlpVirtualUnwind(
	IN ULONG HandlerType,
	IN ULONG64 ImageBase,
	IN ULONG64 ControlPc,
	IN PRUNTIME_FUNCTION FunctionEntry,
	IN OUT PCONTEXT ContextRecord,
	OUT PVOID *HandlerData,
	OUT PULONG64 EstablisherFrame,
	IN OUT PKNONVOLATILE_CONTEXT_POINTERS ContextPointers OPTIONAL
)
{
//
// Define opcode and prefix values.
//

#define SIZE64_PREFIX 0x48
#define ADD_IMM8_OP 0x83
#define ADD_IMM32_OP 0x81
#define JMP_IMM8_OP 0xeb
#define JMP_IMM32_OP 0xe9
#define JMP_IND_OP 0xff
#define LEA_OP 0x8d
#define REP_PREFIX 0xf3
#define POP_OP 0x58
#define RET_OP 0xc3
#define RET_OP_2 0xc2

#define IS_REX_PREFIX(x) (((x) & 0xf0) == 0x40)

	ULONG64 BranchBase;
	ULONG64 BranchTarget;
	LONG Displacement;
	ULONG FrameRegister;
	ULONG Index;
	bool InEpilogue;
	PULONG64 IntegerAddress;
	PULONG64 IntegerRegister;
	PUCHAR NextByte;
	PRUNTIME_FUNCTION PrimaryFunctionEntry;
	ULONG PrologOffset;
	ULONG RegisterNumber;
	PUNWIND_INFO UnwindInfo;
	uint64_t ValueFromAddress;

	RUNTIME_FUNCTION FunctionEntryCell;
	uc_mem_read(m_uc, (uint64_t)FunctionEntry, &FunctionEntryCell, sizeof(FunctionEntryCell));

	UnwindInfo = (PUNWIND_INFO)(FunctionEntryCell.UnwindData + ImageBase);
	PrologOffset = (ULONG)(ControlPc - (FunctionEntryCell.BeginAddress + ImageBase));

	crt_buffer_t UnwindInfoCell(offsetof(UNWIND_INFO, UnwindCode));
	uc_mem_read(m_uc, (uint64_t)UnwindInfo, UnwindInfoCell.GetBuffer(), UnwindInfoCell.GetLength());
	PUNWIND_INFO UnwindInfoCellPtr = (PUNWIND_INFO)UnwindInfoCell.GetBuffer();
	UnwindInfoCell.GetSpace(offsetof(UNWIND_INFO, UnwindCode) + UnwindInfoCellPtr->CountOfCodes * sizeof(UNWIND_CODE) + sizeof(DWORD) * 2);
	uc_mem_read(m_uc, (uint64_t)UnwindInfo, UnwindInfoCell.GetBuffer(), UnwindInfoCell.GetLength());
	UnwindInfoCellPtr = (PUNWIND_INFO)UnwindInfoCell.GetBuffer();

	if (UnwindInfoCellPtr->FrameRegister == 0) {
		*EstablisherFrame = ContextRecord->Rsp;

	}
	else if ((PrologOffset >= UnwindInfoCellPtr->SizeOfProlog) ||
		((UnwindInfoCellPtr->Flags & UNW_FLAG_CHAININFO) != 0)) {

		*EstablisherFrame = (&ContextRecord->Rax)[UnwindInfoCellPtr->FrameRegister];
		*EstablisherFrame -= UnwindInfoCellPtr->FrameOffset * 16;

	}
	else {
		Index = 0;
		while (Index < UnwindInfo->CountOfCodes) {
			if (UnwindInfoCellPtr->UnwindCode[Index].UnwindOp == UWOP_SET_FPREG) {
				break;
			}

			Index += 1;
		}

		if (PrologOffset >= UnwindInfoCellPtr->UnwindCode[Index].CodeOffset) {
			*EstablisherFrame = (&ContextRecord->Rax)[UnwindInfoCellPtr->FrameRegister];
			*EstablisherFrame -= UnwindInfoCellPtr->FrameOffset * 16;

		}
		else {
			*EstablisherFrame = ContextRecord->Rsp;
		}
	}

	//
	// If the point at which control left the specified function is in an
	// epilogue, then emulate the execution of the epilogue forward and
	// return no exception handler.
	//

	IntegerRegister = &ContextRecord->Rax;

	NextByte = (PUCHAR)ControlPc;

	UCHAR NextByteBuffer[15];
	uc_mem_read(m_uc, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
	//
	// Check for one of:
	//
	//   add rsp, imm8
	//       or
	//   add rsp, imm32
	//       or
	//   lea rsp, -disp8[fp]
	//       or
	//   lea rsp, -disp32[fp]
	//

	if ((NextByteBuffer[0] == SIZE64_PREFIX) &&
		(NextByteBuffer[1] == ADD_IMM8_OP) &&
		(NextByteBuffer[2] == 0xc4)) {

		//
		// add rsp, imm8.
		//

		NextByte += 4;
		uc_mem_read(m_uc, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
	}
	else if ((NextByteBuffer[0] == SIZE64_PREFIX) &&
		(NextByteBuffer[1] == ADD_IMM32_OP) &&
		(NextByteBuffer[2] == 0xc4)) {

		//
		// add rsp, imm32.
		//

		NextByte += 7;
		uc_mem_read(m_uc, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
	}
	else if (((NextByteBuffer[0] & 0xfe) == SIZE64_PREFIX) &&
		(NextByteBuffer[1] == LEA_OP)) {

		FrameRegister = ((NextByteBuffer[0] & 0x1) << 3) | (NextByteBuffer[2] & 0x7);
		if ((FrameRegister != 0) &&
			(FrameRegister == UnwindInfoCellPtr->FrameRegister)) {

			if ((NextByteBuffer[2] & 0xf8) == 0x60) {

				//
				// lea rsp, disp8[fp].
				//

				NextByte += 4;
				uc_mem_read(m_uc, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
			}
			else if ((NextByteBuffer[2] & 0xf8) == 0xa0) {

				//
				// lea rsp, disp32[fp].
				//

				NextByte += 7;
				uc_mem_read(m_uc, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
			}
		}
	}

	//
	// Check for any number of:
	//
	//   pop nonvolatile-integer-register[0..15].
	//

	while (TRUE) {
		if ((NextByteBuffer[0] & 0xf8) == POP_OP) {
			NextByte += 1;
			uc_mem_read(m_uc, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
		}
		else if (IS_REX_PREFIX(NextByteBuffer[0]) &&
			((NextByteBuffer[1] & 0xf8) == POP_OP)) {

			NextByte += 2;
			uc_mem_read(m_uc, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
		}
		else {
			break;
		}
	}

	//
	// If the next instruction is a return or an appropriate jump, then
	// control is currently in an epilogue and execution of the epilogue
	// should be emulated. Otherwise, execution is not in an epilogue and
	// the prologue should be unwound.
	//

	InEpilogue = FALSE;
	if ((NextByteBuffer[0] == RET_OP) ||
		(NextByteBuffer[0] == RET_OP_2) ||
		((NextByteBuffer[0] == REP_PREFIX) && (NextByteBuffer[1] == RET_OP))) {

		//
		// A return is an unambiguous indication of an epilogue.
		//

		InEpilogue = TRUE;

	}
	else if ((NextByteBuffer[0] == JMP_IMM8_OP) || (NextByteBuffer[0] == JMP_IMM32_OP)) {

		//
		// An unconditional branch to a target that is equal to the start of
		// or outside of this routine is logically a call to another function.
		// 

		BranchTarget = (ULONG64)NextByte - ImageBase;
		if (NextByteBuffer[0] == JMP_IMM8_OP) {
			BranchTarget += 2 + (CHAR)NextByteBuffer[1];

		}
		else {
			BranchTarget += 5 + *((LONG UNALIGNED *)&NextByteBuffer[1]);
		}

		//
		// Determine whether the branch target refers to code within this
		// function. If not, then it is an epilogue indicator.
		//
		// A branch to the start of self implies a recursive call, so
		// is treated as an epilogue.
		//

		if (BranchTarget < FunctionEntryCell.BeginAddress ||
			BranchTarget >= FunctionEntryCell.EndAddress) {

			//
			// The branch target is outside of the region described by
			// this function entry. See whether it is contained within
			// an indirect function entry associated with this same
			// function.
			//
			// If not, then the branch target really is outside of
			// this function.
			//

			PrimaryFunctionEntry = RtlpSameFunction(FunctionEntry,
				ImageBase,
				BranchTarget + ImageBase);

			RUNTIME_FUNCTION PrimaryFunctionEntryCell;
			uc_mem_read(m_uc, (uint64_t)PrimaryFunctionEntry, &PrimaryFunctionEntryCell, sizeof(PrimaryFunctionEntryCell));

			if ((PrimaryFunctionEntry == NULL) ||
				(BranchTarget == PrimaryFunctionEntryCell.BeginAddress)) {

				InEpilogue = TRUE;
			}

		}
		else if ((BranchTarget == FunctionEntryCell.BeginAddress) &&
			((UnwindInfoCellPtr->Flags & UNW_FLAG_CHAININFO) == 0)) {

			InEpilogue = TRUE;
		}

	}
	else if ((NextByteBuffer[0] == JMP_IND_OP) && (NextByteBuffer[1] == 0x25)) {

		//
		// An unconditional jump indirect.
		//
		// This is a jmp outside of the function, probably a tail call
		// to an import function.
		//

		InEpilogue = TRUE;

	}
	else if (((NextByteBuffer[0] & 0xf8) == SIZE64_PREFIX) &&
		(NextByteBuffer[1] == 0xff) &&
		(NextByteBuffer[2] & 0x38) == 0x20) {

		//
		// This is an indirect jump opcode: 0x48 0xff /4.  The 64-bit
		// flag (REX.W) is always redundant here, so its presence is
		// overloaded to indicate a branch out of the function - a tail
		// call.
		//
		// Such an opcode is an unambiguous epilogue indication.
		//

		InEpilogue = TRUE;
	}

	if (InEpilogue != FALSE) {
		NextByte = (PUCHAR)ControlPc;
		uc_mem_read(m_uc, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
		//
		// Emulate one of (if any):
		//
		//   add rsp, imm8
		//       or
		//   add rsp, imm32
		//       or                
		//   lea rsp, disp8[frame-register]
		//       or
		//   lea rsp, disp32[frame-register]
		//

		if ((NextByteBuffer[0] & 0xf8) == SIZE64_PREFIX) {

			if (NextByteBuffer[1] == ADD_IMM8_OP) {

				//
				// add rsp, imm8.
				//

				ContextRecord->Rsp += (CHAR)NextByteBuffer[3];
				NextByte += 4;
				uc_mem_read(m_uc, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
			}
			else if (NextByteBuffer[1] == ADD_IMM32_OP) {

				//
				// add rsp, imm32.
				//

				Displacement = NextByteBuffer[3] | (NextByteBuffer[4] << 8);
				Displacement |= (NextByteBuffer[5] << 16) | (NextByteBuffer[6] << 24);
				ContextRecord->Rsp += Displacement;
				NextByte += 7;
				uc_mem_read(m_uc, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
			}
			else if (NextByteBuffer[1] == LEA_OP) {
				if ((NextByteBuffer[2] & 0xf8) == 0x60) {

					//
					// lea rsp, disp8[frame-register].
					//

					ContextRecord->Rsp = IntegerRegister[FrameRegister];
					ContextRecord->Rsp += (CHAR)NextByteBuffer[3];
					NextByte += 4;
					uc_mem_read(m_uc, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
				}
				else if ((NextByteBuffer[2] & 0xf8) == 0xa0) {

					//
					// lea rsp, disp32[frame-register].
					//

					Displacement = NextByteBuffer[3] | (NextByteBuffer[4] << 8);
					Displacement |= (NextByteBuffer[5] << 16) | (NextByteBuffer[6] << 24);
					ContextRecord->Rsp = IntegerRegister[FrameRegister];
					ContextRecord->Rsp += Displacement;
					NextByte += 7;
					uc_mem_read(m_uc, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
				}
			}
		}

		//
		// Emulate any number of (if any):
		//
		//   pop nonvolatile-integer-register.
		//

		while (TRUE) {
			if ((NextByteBuffer[0] & 0xf8) == POP_OP) {

				//
				// pop nonvolatile-integer-register[0..7]
				//

				RegisterNumber = NextByteBuffer[0] & 0x7;
				
				IntegerAddress = (PULONG64)ContextRecord->Rsp;

				uint64_t ValueFromAddress;
				uc_mem_read(m_uc, (uint64_t)IntegerAddress, &ValueFromAddress, sizeof(ValueFromAddress));

				IntegerRegister[RegisterNumber] = ValueFromAddress;
				if (ContextPointers) {
					ContextPointers->IntegerContext[RegisterNumber] = IntegerAddress;
				}

				ContextRecord->Rsp += 8;
				NextByte += 1;

			}
			else if (IS_REX_PREFIX(NextByteBuffer[0]) &&
				((NextByteBuffer[1] & 0xf8) == POP_OP)) {

				//
				// pop nonvolatile-integer-register[8..15]
				//

				RegisterNumber = ((NextByteBuffer[0] & 1) << 3) | (NextByteBuffer[1] & 0x7);

				IntegerAddress = (PULONG64)ContextRecord->Rsp;
				
				uc_mem_read(m_uc, (uint64_t)IntegerAddress, &ValueFromAddress, sizeof(ValueFromAddress));
				
				IntegerRegister[RegisterNumber] = ValueFromAddress;

				if (ContextPointers) {
					ContextPointers->IntegerContext[RegisterNumber] = IntegerAddress;
				}

				ContextRecord->Rsp += 8;
				NextByte += 2;
				uc_mem_read(m_uc, (uint64_t)NextByte, NextByteBuffer, sizeof(NextByteBuffer));
			}
			else {
				break;
			}
		}

		//
		// Emulate return and return null exception handler.
		//
		// Note: this instruction might in fact be a jmp, however
		//       we want to emulate a return regardless.
		//

		uint64_t ValueFromRsp;
		uc_mem_read(m_uc, (uint64_t)ContextRecord->Rsp, &ValueFromRsp, sizeof(ValueFromRsp));
		ContextRecord->Rip = ValueFromRsp;
		ContextRecord->Rsp += 8;
		return NULL;
	}

	//
	// Control left the specified function outside an epilogue. Unwind the
	// subject function and any chained unwind information.
	//

	FunctionEntry = RtlpUnwindPrologue(ImageBase,
		ControlPc,
		*EstablisherFrame,
		FunctionEntry,
		ContextRecord,
		ContextPointers);

	uc_mem_read(m_uc, (uint64_t)FunctionEntry, &FunctionEntryCell, sizeof(FunctionEntryCell));

	//
	// If control left the specified function outside of the prologue and
	// the function has a handler that matches the specified type, then
	// return the address of the language specific exception handler.
	// Otherwise, return NULL.
	//

	UnwindInfo = (PUNWIND_INFO)(FunctionEntryCell.UnwindData + ImageBase);

	uc_mem_read(m_uc, (uint64_t)UnwindInfo, UnwindInfoCell.GetBuffer(), UnwindInfoCell.GetLength());
	UnwindInfoCellPtr = (PUNWIND_INFO)UnwindInfoCell.GetBuffer();
	UnwindInfoCell.GetSpace(offsetof(UNWIND_INFO, UnwindCode) + UnwindInfoCellPtr->CountOfCodes * sizeof(UNWIND_CODE) + sizeof(DWORD) * 2);
	uc_mem_read(m_uc, (uint64_t)UnwindInfo, UnwindInfoCell.GetBuffer(), UnwindInfoCell.GetLength());
	UnwindInfoCellPtr = (PUNWIND_INFO)UnwindInfoCell.GetBuffer();

	PrologOffset = (ULONG)(ControlPc - (FunctionEntryCell.BeginAddress + ImageBase));
	if ((PrologOffset >= UnwindInfoCellPtr->SizeOfProlog) &&
		((UnwindInfoCellPtr->Flags & HandlerType) != 0)) {
		Index = UnwindInfoCellPtr->CountOfCodes;
		if ((Index & 1) != 0) {
			Index += 1;
		}

		*HandlerData = (PVOID)((PUCHAR)UnwindInfo + ((PUCHAR)&UnwindInfoCellPtr->UnwindCode[Index + 2] - (PUCHAR)UnwindInfoCellPtr));
		return (PEXCEPTION_ROUTINE)(*((PULONG)&UnwindInfoCellPtr->UnwindCode[Index]) + ImageBase);

	}
	else {
		return NULL;
	}
}

BOOLEAN PeEmulation::RtlpDispatchException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord
){

	BOOLEAN Completion = FALSE;
	CONTEXT ContextRecord1;
	ULONG64 ControlPc;
	DISPATCHER_CONTEXT DispatcherContext;
	EXCEPTION_DISPOSITION Disposition;
	ULONG64 EstablisherFrame;
	ULONG ExceptionFlags;
	PEXCEPTION_ROUTINE ExceptionRoutine;
	PRUNTIME_FUNCTION FunctionEntry;
	PVOID HandlerData;
	ULONG64 HighLimit;
	PUNWIND_HISTORY_TABLE HistoryTable;
	ULONG64 ImageBase;
	ULONG64 LowLimit;
	ULONG64 NestedFrame;
	BOOLEAN Repeat;
	ULONG ScopeIndex;
	UNWIND_HISTORY_TABLE UnwindTable;

	//
	// Get current stack limits, copy the context record, get the initial
	// PC value, capture the exception flags, and set the nested exception
	// frame pointer.
	//

	RtlpGetStackLimits(&LowLimit, &HighLimit);
	RtlpCopyContext(&ContextRecord1, ContextRecord);
	ControlPc = (ULONG64)ExceptionRecord->ExceptionAddress;
	ExceptionFlags = ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE;
	NestedFrame = 0;

	//
	// Initialize the unwind history table.
	//

	HistoryTable = &UnwindTable;
	HistoryTable->Count = 0;
	HistoryTable->Search = UNWIND_HISTORY_TABLE_NONE;
	HistoryTable->LowAddress = -1;
	HistoryTable->HighAddress = 0;

	//
	// Start with the frame specified by the context record and search
	// backwards through the call frame hierarchy attempting to find an
	// exception handler that will handle the exception.
	//

	do {

		//
		// Lookup the function table entry using the point at which control
		// left the procedure.
		//

		FunctionEntry = RtlpLookupFunctionEntry(ControlPc,
			&ImageBase,
			HistoryTable);

		//
		// If there is a function table entry for the routine, then virtually
		// unwind to the caller of the current routine to obtain the virtual
		// frame pointer of the establisher and check if there is an exception
		// handler for the frame.
		//

		if (FunctionEntry != NULL) {
			ExceptionRoutine = RtlpVirtualUnwind(UNW_FLAG_EHANDLER,
				ImageBase,
				ControlPc,
				FunctionEntry,
				&ContextRecord1,
				&HandlerData,
				&EstablisherFrame,
				NULL);

			//
			// If the establisher frame pointer is not within the specified
			// stack limits or the established frame pointer is unaligned,
			// then set the stack invalid flag in the exception record and
			// return exception not handled. Otherwise, check if the current
			// routine has an exception handler.
			//

			if (RtlpIsFrameInBounds(&LowLimit, EstablisherFrame, &HighLimit) == FALSE) {
				ExceptionFlags |= EXCEPTION_STACK_INVALID;
				break;

			}
			else if (ExceptionRoutine != NULL) {

				//
				// The frame has an exception handler.
				//
				// A linkage routine written in assembler is used to actually
				// call the actual exception handler. This is required by the
				// exception handler that is associated with the linkage
				// routine so it can have access to two sets of dispatcher
				// context when it is called.
				//
				// Call the language specific handler.
				//

				ScopeIndex = 0;
				do {

					//
					// Log the exception if exception logging is enabled.
					//

					ExceptionRecord->ExceptionFlags = ExceptionFlags;


					//
					// Clear repeat, set the dispatcher context, and call the
					// exception handler.
					//

					Repeat = FALSE;
					DispatcherContext.ControlPc = ControlPc;
					DispatcherContext.ImageBase = ImageBase;
					DispatcherContext.FunctionEntry = FunctionEntry;
					DispatcherContext.EstablisherFrame = EstablisherFrame;
					DispatcherContext.ContextRecord = &ContextRecord1;
					DispatcherContext.LanguageHandler = ExceptionRoutine;
					DispatcherContext.HandlerData = HandlerData;
					DispatcherContext.HistoryTable = HistoryTable;
					DispatcherContext.ScopeIndex = ScopeIndex;

					//
					Disposition = RtlpExecuteHandlerForException(
						ExceptionRecord, (PVOID)EstablisherFrame, 
						ContextRecord, &DispatcherContext);
					
					//
					// Propagate noncontinuable exception flag.
					//

					ExceptionFlags |=
						(ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE);

					if (m_ExecuteExceptionHandler == 2)
					{
						m_ExecuteExceptionHandler = 0;
						Completion = TRUE;
						goto DispatchExit;
					}

					//
					// If the current scan is within a nested context and the
					// frame just examined is the end of the nested region,
					// then clear the nested context frame and the nested
					// exception flag in the exception flags.
					//

					if (NestedFrame == EstablisherFrame) {
						ExceptionFlags &= (~EXCEPTION_NESTED_CALL);
						NestedFrame = 0;
					}

					//
					// Case on the handler disposition.
					//

					switch (Disposition) {

						//
						// The disposition is to continue execution.
						//
						// If the exception is not continuable, then raise
						// the exception STATUS_NONCONTINUABLE_EXCEPTION.
						// Otherwise return exception handled.
						//

					case ExceptionContinueExecution:
						if ((ExceptionFlags & EXCEPTION_NONCONTINUABLE) != 0) {
							RtlRaiseStatus(STATUS_NONCONTINUABLE_EXCEPTION);

						}
						else {
							Completion = TRUE;
							goto DispatchExit;
						}

						//
						// The disposition is to continue the search.
						//
						// Get next frame address and continue the search.
						//

					case ExceptionContinueSearch:
						break;

						//
						// The disposition is nested exception.
						//
						// Set the nested context frame to the establisher frame
						// address and set the nested exception flag in the
						// exception flags.
						//

					case ExceptionNestedException:
						ExceptionFlags |= EXCEPTION_NESTED_CALL;
						if (DispatcherContext.EstablisherFrame > NestedFrame) {
							NestedFrame = DispatcherContext.EstablisherFrame;
						}

						break;

						//
						// The dispostion is collided unwind.
						//
						// A collided unwind occurs when an exception dispatch
						// encounters a previous call to an unwind handler. In
						// this case the previous unwound frames must be skipped.
						//

					case ExceptionCollidedUnwind:
						ControlPc = DispatcherContext.ControlPc;
						ImageBase = DispatcherContext.ImageBase;
						FunctionEntry = DispatcherContext.FunctionEntry;
						EstablisherFrame = DispatcherContext.EstablisherFrame;
						RtlpCopyContext(&ContextRecord1,
							DispatcherContext.ContextRecord);

						ContextRecord1.Rip = ControlPc;
						ExceptionRoutine = DispatcherContext.LanguageHandler;
						HandlerData = DispatcherContext.HandlerData;
						HistoryTable = DispatcherContext.HistoryTable;
						ScopeIndex = DispatcherContext.ScopeIndex;
						Repeat = TRUE;
						break;

						//
						// All other disposition values are invalid.
						//
						// Raise invalid disposition exception.
						//

					default:
						RtlRaiseStatus(STATUS_INVALID_DISPOSITION);
					}

				} while (Repeat != FALSE);
			}

		}
		else {

			//
			// If the old control PC is the same as the return address,
			// then no progress is being made and the function tables are
			// most likely malformed.
			//

			uint64_t ValueFromRsp;
			uc_mem_read(m_uc, ContextRecord1.Rsp, &ValueFromRsp, sizeof(ValueFromRsp));
			if (ControlPc == ValueFromRsp) {
				break;
			}

			//
			// Set the point where control left the current function by
			// obtaining the return address from the top of the stack.
			//

			ContextRecord1.Rip = ValueFromRsp;
			ContextRecord1.Rsp += 8;
		}

		//
		// Set point at which control left the previous routine.
		//

		ControlPc = ContextRecord1.Rip;
	} while (RtlpIsFrameInBounds(&LowLimit, (ULONG64)ContextRecord1.Rsp, &HighLimit) == TRUE);

	//
	// Set final exception flags and return exception not handled.
	//

	ExceptionRecord->ExceptionFlags = ExceptionFlags;

	//
	// Call vectored continue handlers.
	//

DispatchExit:

	return Completion;
}

VOID PeEmulation::RtlpUnwindEx(
	IN PVOID TargetFrame OPTIONAL,
	IN PVOID TargetIp OPTIONAL,
	IN PEXCEPTION_RECORD ExceptionRecord OPTIONAL,
	IN PVOID ReturnValue,
	IN PCONTEXT OriginalContext,
	IN PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL
)
{

	ULONG64 ControlPc;
	PCONTEXT CurrentContext;
	DISPATCHER_CONTEXT DispatcherContext;
	EXCEPTION_DISPOSITION Disposition;
	ULONG64 EstablisherFrame;
	ULONG ExceptionFlags;
	EXCEPTION_RECORD ExceptionRecord1;
	PEXCEPTION_ROUTINE ExceptionRoutine;
	PRUNTIME_FUNCTION FunctionEntry;
	PVOID HandlerData;
	ULONG64 HighLimit;
	ULONG64 ImageBase;
	CONTEXT LocalContext;
	ULONG64 LowLimit;
	PCONTEXT PreviousContext;
	ULONG ScopeIndex;
	PCONTEXT TempContext;

	uint64_t ValueFromAddress;
	//
	// Get current stack limits, capture the current context, virtually
	// unwind to the caller of this routine, get the initial PC value, and
	// set the unwind target address.
	//

	CurrentContext = OriginalContext;
	PreviousContext = &LocalContext;
	RtlpGetStackLimits(&LowLimit, &HighLimit);
	RtlpCaptureContext(CurrentContext);

	CurrentContext->Rip = (ULONG64)TargetIp;
	CurrentContext->Rsp = (ULONG64)TargetFrame;
	//
	// If a history table is specified, then set to search history table.
	//

	if (HistoryTable) {
		HistoryTable->Search = UNWIND_HISTORY_TABLE_GLOBAL;
	}

	//
	// If an exception record is not specified, then build a local exception
	// record for use in calling exception handlers during the unwind operation.
	//

	if (!ExceptionRecord) {
		ExceptionRecord = &ExceptionRecord1;
		ExceptionRecord1.ExceptionCode = STATUS_UNWIND;
		ExceptionRecord1.ExceptionRecord = NULL;
		ExceptionRecord1.ExceptionAddress = (PVOID)CurrentContext->Rip;
		ExceptionRecord1.NumberParameters = 0;
	}

	//
	// If the target frame of the unwind is specified, then a normal unwind
	// is being performed. Otherwise, an exit unwind is being performed.
	//

	ExceptionFlags = EXCEPTION_UNWINDING;
	if (!TargetFrame) {
		ExceptionFlags |= EXCEPTION_EXIT_UNWIND;
	}

	//
	// Scan backward through the call frame hierarchy and call exception
	// handlers until the target frame of the unwind is reached.
	//

	do {

		//
		// Lookup the function table entry using the point at which control
		// left the procedure.
		//

		ControlPc = CurrentContext->Rip;
		FunctionEntry = RtlpLookupFunctionEntry(ControlPc,
			&ImageBase,
			HistoryTable);

		//
		// If there is a function table entry for the routine, then virtually
		// unwind to the caller of the routine to obtain the virtual frame
		// pointer of the establisher, but don't update the context record.
		//

		if (FunctionEntry != NULL) {
			RtlpCopyContext(PreviousContext, CurrentContext);
			ExceptionRoutine = RtlpVirtualUnwind(UNW_FLAG_UHANDLER,
				ImageBase,
				ControlPc,
				FunctionEntry,
				PreviousContext,
				&HandlerData,
				&EstablisherFrame,
				NULL);

			//
			// If the establisher frame pointer is not within the specified
			// stack limits, the establisher frame pointer is unaligned, or
			// the target frame is below the establisher frame and an exit
			// unwind is not being performed, then raise a bad stack status.
			// Otherwise, check to determine if the current routine has an
			// exception handler.
			//

			if ((RtlpIsFrameInBounds(&LowLimit, EstablisherFrame, &HighLimit) == FALSE) ||
				(!TargetFrame &&
				((ULONG64)TargetFrame < EstablisherFrame))) {

				RtlRaiseStatus(STATUS_BAD_STACK);

			}
			else if (ExceptionRoutine != NULL) {

				//
				// The frame has a exception handler.
				//
				// A linkage routine written in assembler is used to actually
				// call the actual exception handler. This is required by the
				// exception handler that is associated with the linkage
				// routine so it can have access to two sets of dispatcher
				// context when it is called.
				//
				// Call the language specific handler.
				//

				DispatcherContext.TargetIp = (ULONG64)TargetIp;
				ScopeIndex = 0;
				do {

					//
					// If the establisher frame is the target of the unwind
					// operation, then set the target unwind flag.
					//

					if ((ULONG64)TargetFrame == EstablisherFrame) {
						ExceptionFlags |= EXCEPTION_TARGET_UNWIND;
					}

					//ExceptionRecord->ExceptionFlags = ExceptionFlags;
					uc_mem_write(m_uc, (uint64_t)ExceptionRecord + offsetof(EXCEPTION_RECORD, ExceptionFlags), &ExceptionFlags, sizeof(ExceptionFlags));

					//
					// Set the specified return value and target IP in case
					// the exception handler directly continues execution.
					//

					CurrentContext->Rax = (ULONG64)ReturnValue;

					//
					// Set the dispatcher context and call the termination
					// handler.
					//

					DispatcherContext.ControlPc = ControlPc;
					DispatcherContext.ImageBase = ImageBase;
					DispatcherContext.FunctionEntry = FunctionEntry;
					DispatcherContext.EstablisherFrame = EstablisherFrame;
					DispatcherContext.ContextRecord = CurrentContext;
					DispatcherContext.LanguageHandler = ExceptionRoutine;
					DispatcherContext.HandlerData = HandlerData;
					DispatcherContext.HistoryTable = HistoryTable;
					DispatcherContext.ScopeIndex = ScopeIndex;
					Disposition = RtlpExecuteHandlerForException(ExceptionRecord,
							(PVOID)EstablisherFrame,
							CurrentContext,
							&DispatcherContext);

					//
					// Clear target unwind and collided unwind flags.
					//

					ExceptionFlags &=
						~(EXCEPTION_COLLIDED_UNWIND | EXCEPTION_TARGET_UNWIND);

					//
					// Case on the handler disposition.
					//

					switch (Disposition) {

						//
						// The disposition is to continue the search.
						//
						// If the target frame has not been reached, then
						// swap context pointers.
						//

					case ExceptionContinueSearch:
						if (EstablisherFrame != (ULONG64)TargetFrame) {
							TempContext = CurrentContext;
							CurrentContext = PreviousContext;
							PreviousContext = TempContext;
						}

						break;

						//
						// The disposition is collided unwind.
						//
						// Copy the context of the previous unwind and
						// virtually unwind to the caller of the establisher,
						// then set the target of the current unwind to the
						// dispatcher context of the previous unwind, and
						// reexecute the exception handler from the collided
						// frame with the collided unwind flag set in the
						// exception record.
						//

					case ExceptionCollidedUnwind:
						ControlPc = DispatcherContext.ControlPc;
						ImageBase = DispatcherContext.ImageBase;
						FunctionEntry = DispatcherContext.FunctionEntry;
						RtlpCopyContext(OriginalContext,
							DispatcherContext.ContextRecord);

						CurrentContext = OriginalContext;
						PreviousContext = &LocalContext;
						RtlpCopyContext(PreviousContext, CurrentContext);
						RtlpVirtualUnwind(UNW_FLAG_NHANDLER,
							ImageBase,
							ControlPc,
							FunctionEntry,
							PreviousContext,
							&HandlerData,
							&EstablisherFrame,
							NULL);

						EstablisherFrame = DispatcherContext.EstablisherFrame;
						ExceptionRoutine = DispatcherContext.LanguageHandler;
						HandlerData = DispatcherContext.HandlerData;
						HistoryTable = DispatcherContext.HistoryTable;
						ScopeIndex = DispatcherContext.ScopeIndex;
						ExceptionFlags |= EXCEPTION_COLLIDED_UNWIND;
						break;

						//
						// All other disposition values are invalid.
						//
						// Raise invalid disposition exception.
						//

					default:
						RtlRaiseStatus(STATUS_INVALID_DISPOSITION);
					}

				} while ((ExceptionFlags & EXCEPTION_COLLIDED_UNWIND) != 0);

			}
			else {

				//
				// If the target frame has not been reached, then swap
				// context pointers.
				//

				if (EstablisherFrame != (ULONG64)TargetFrame) {
					TempContext = CurrentContext;
					CurrentContext = PreviousContext;
					PreviousContext = TempContext;
				}
			}

		}
		else {

			//
			// Set the point where control left the current function by
			// obtaining the return address from the top of the stack.
			//

			uc_mem_read(m_uc, (uint64_t)CurrentContext->Rsp, &ValueFromAddress, sizeof(ValueFromAddress));

			CurrentContext->Rip = ValueFromAddress;
			CurrentContext->Rsp += 8;
		}

	} while ((RtlpIsFrameInBounds(&LowLimit, EstablisherFrame, &HighLimit) == TRUE) &&
		(EstablisherFrame != (ULONG64)TargetFrame));

	//
	// If the establisher stack pointer is equal to the target frame pointer,
	// then continue execution. Otherwise, an exit unwind was performed or the
	// target of the unwind did not exist and the debugger and subsystem are
	// given a second chance to handle the unwind.
	//

	if (EstablisherFrame == (ULONG64)TargetFrame) {
		CurrentContext->Rax = (ULONG64)ReturnValue;

		ULONG ExceptionCode;
		uc_mem_read(m_uc, (uint64_t)ExceptionRecord + offsetof(EXCEPTION_RECORD, ExceptionCode), &ExceptionCode, sizeof(ExceptionCode));

		if (ExceptionCode != STATUS_UNWIND_CONSOLIDATE) {
			CurrentContext->Rip = (ULONG64)TargetIp;
		}

		RtlpRestoreContext(CurrentContext, ExceptionRecord);
	}
	else {

		//
		// If the old control PC is the same as the new control PC, then
		// no progress is being made and the function tables are most likely
		// malformed. Otherwise, give the debugger and subsystem a second
		// chance to handle the exception.

		if (ControlPc == CurrentContext->Rip) {
			RtlRaiseStatus(STATUS_BAD_FUNCTION_TABLE);

		}
		else {
			RaiseException(ExceptionRecord, CurrentContext, FALSE);
		}
	}
}

EXCEPTION_DISPOSITION PeEmulation::RtlpExecuteHandlerForException(
	_Inout_ struct _EXCEPTION_RECORD *ExceptionRecord,
	_In_ PVOID EstablisherFrame,
	_Inout_ struct _CONTEXT *ContextRecord,
	_In_ PDISPATCHER_CONTEXT DispatcherContext
)
{
	EXCEPTION_DISPOSITION dispo = ExceptionContinueExecution;
	auto ExceptionRecordBase = StackAlloc(sizeof(EXCEPTION_RECORD));
	auto ContextRecordBase = StackAlloc(sizeof(CONTEXT));
	auto DispatcherContextBase = StackAlloc(sizeof(DISPATCHER_CONTEXT));

	uc_mem_write(m_uc, ExceptionRecordBase, ExceptionRecord, sizeof(EXCEPTION_RECORD));
	uc_mem_write(m_uc, ContextRecordBase, ContextRecord, sizeof(CONTEXT));
	uc_mem_write(m_uc, DispatcherContextBase, DispatcherContext, sizeof(DISPATCHER_CONTEXT));

	uc_reg_write(m_uc, UC_X86_REG_RCX, &ExceptionRecordBase);
	uc_reg_write(m_uc, UC_X86_REG_RDX, &EstablisherFrame);
	uc_reg_write(m_uc, UC_X86_REG_R8, &ContextRecordBase);
	uc_reg_write(m_uc, UC_X86_REG_R9, &DispatcherContextBase);

	uint64_t retAddr = StackAlloc(sizeof(m_ImageEnd));
	uc_mem_write(m_uc, retAddr, &m_ImageEnd, sizeof(m_ImageEnd));
	StackAlloc(7 * sizeof(ULONG64));
	//push m_ImageEnd
	//sub rsp, 7 * dq

	auto err = uc_emu_start(m_uc, (uint64_t)DispatcherContext->LanguageHandler, m_ImageEnd, 0, 0);

	if (m_ExecuteExceptionHandler == 1)
	{
		m_ExecuteExceptionHandler = 0;
		return C_specific_handler();
	}

	//add rsp, 7 * dq
	StackFree(7 * sizeof(ULONG64));

	uc_mem_read(m_uc, ExceptionRecordBase, ExceptionRecord, sizeof(EXCEPTION_RECORD));
	uc_mem_read(m_uc, ContextRecordBase, ContextRecord, sizeof(CONTEXT));
	uc_mem_read(m_uc, DispatcherContextBase, DispatcherContext, sizeof(DISPATCHER_CONTEXT));

	StackFree(sizeof(EXCEPTION_RECORD));
	StackFree(sizeof(CONTEXT));
	StackFree(sizeof(DISPATCHER_CONTEXT));

	return dispo;
}

EXCEPTION_DISPOSITION PeEmulation::C_specific_handler(VOID)
{
	ULONG_PTR ControlPc = 0;
	PEXCEPTION_FILTER ExceptionFilter = NULL;
	EXCEPTION_POINTERS ExceptionPointers = { 0 };
	ULONG_PTR ImageBase = 0;
	ULONG_PTR Handler = 0;
	ULONG Index = 0;
	PSCOPE_TABLE ScopeTable = NULL;
	ULONG TargetIndex = 0;
	ULONG_PTR TargetPc = 0;
	PTERMINATION_HANDLER TerminationHandler = NULL;
	LONG Value = 0;

	uint64_t ExceptionRecordBase;
	uc_reg_read(m_uc, UC_X86_REG_RCX, &ExceptionRecordBase);
	EXCEPTION_RECORD ExceptionRecord;
	uc_mem_read(m_uc, ExceptionRecordBase, &ExceptionRecord, sizeof(EXCEPTION_RECORD));

	uint64_t EstablisherFrame;
	uc_reg_read(m_uc, UC_X86_REG_RDX, &EstablisherFrame);

	uint64_t ContextRecordBase;
	uc_reg_read(m_uc, UC_X86_REG_R8, &ContextRecordBase);
	CONTEXT ContextRecord;
	uc_mem_read(m_uc, ContextRecordBase, &ContextRecord, sizeof(CONTEXT));

	uint64_t DispatcherContextBase;
	uc_reg_read(m_uc, UC_X86_REG_R9, &DispatcherContextBase);
	DISPATCHER_CONTEXT DispatcherContext;
	uc_mem_read(m_uc, DispatcherContextBase, &DispatcherContext, sizeof(DISPATCHER_CONTEXT));

	ImageBase = DispatcherContext.ImageBase;
	ControlPc = DispatcherContext.ControlPc - ImageBase;
	ScopeTable = (PSCOPE_TABLE)(DispatcherContext.HandlerData);

	typedef struct {
		DWORD BeginAddress;
		DWORD EndAddress;
		DWORD HandlerAddress;
		DWORD JumpTarget;
	} ScopeRecord_t;

	crt_buffer_t ScopeTableCell(offsetof(SCOPE_TABLE, ScopeRecord));
	uc_mem_read(m_uc, (uint64_t)ScopeTable, ScopeTableCell.GetBuffer(), ScopeTableCell.GetLength());
	PSCOPE_TABLE ScopeTableCellPtr = (PSCOPE_TABLE)ScopeTableCell.GetBuffer();
	ScopeTableCell.GetSpace(offsetof(SCOPE_TABLE, ScopeRecord) + ScopeTableCellPtr->Count * sizeof(ScopeRecord_t));
	uc_mem_read(m_uc, (uint64_t)ScopeTable, ScopeTableCell.GetBuffer(), ScopeTableCell.GetLength());
	ScopeTableCellPtr = (PSCOPE_TABLE)ScopeTableCell.GetBuffer();

	if (IS_DISPATCHING(ExceptionRecord.ExceptionFlags)) {
		ExceptionPointers.ExceptionRecord = (PEXCEPTION_RECORD)ExceptionRecordBase;
		ExceptionPointers.ContextRecord = (PCONTEXT)ContextRecordBase;

		for (Index = DispatcherContext.ScopeIndex;
			Index < ScopeTableCellPtr->Count;
			Index += 1) {
			if ((ControlPc >= ScopeTableCellPtr->ScopeRecord[Index].BeginAddress) &&
				(ControlPc < ScopeTableCellPtr->ScopeRecord[Index].EndAddress) &&
				(ScopeTableCellPtr->ScopeRecord[Index].JumpTarget != 0)) {
				if (ScopeTableCellPtr->ScopeRecord[Index].HandlerAddress == 1) {
					Value = EXCEPTION_EXECUTE_HANDLER;
				}
				else {
					ExceptionFilter = (PEXCEPTION_FILTER)
						(ScopeTableCellPtr->ScopeRecord[Index].HandlerAddress + ImageBase);

					//Value = ExceptionFilter(&ExceptionPointers, (PVOID)EstablisherFrame);
					auto ExceptionPointersBase = StackAlloc(sizeof(ExceptionPointers));
					uc_mem_write(m_uc, ExceptionPointersBase, &ExceptionPointers, sizeof(ExceptionPointers));

					uc_reg_write(m_uc, UC_X86_REG_RCX, &ExceptionPointersBase);
					uc_reg_write(m_uc, UC_X86_REG_RDX, &EstablisherFrame);

					uint64_t retAddr = StackAlloc(sizeof(m_ImageEnd));
					uc_mem_write(m_uc, retAddr, &m_ImageEnd, sizeof(m_ImageEnd));
					
					auto err = uc_emu_start(m_uc, (uint64_t)ExceptionFilter, m_ImageEnd, 0, 0);

					StackFree(sizeof(ExceptionPointers));

					uc_reg_read(m_uc, UC_X86_REG_RAX, &Value);
				}

				if (Value < 0) {
					return ExceptionContinueExecution;
				}
				else if (Value > 0) {

					RtlpUnwindEx(
						(PVOID)EstablisherFrame,
						(PVOID)(ScopeTableCellPtr->ScopeRecord[Index].JumpTarget + ImageBase),
						(PEXCEPTION_RECORD)ExceptionRecordBase,
						(PVOID)((ULONG_PTR)ExceptionRecord.ExceptionCode),
						(PCONTEXT)DispatcherContext.ContextRecord,
						DispatcherContext.HistoryTable);

					m_ExecuteExceptionHandler = 2;

					return ExceptionContinueExecution;
				}
			}
		}
	}
	else {

		TargetPc = DispatcherContext.TargetIp - ImageBase;

		for (Index = DispatcherContext.ScopeIndex;
			Index < ScopeTableCellPtr->Count;
			Index += 1) {
			if ((ControlPc >= ScopeTableCellPtr->ScopeRecord[Index].BeginAddress) &&
				(ControlPc < ScopeTableCellPtr->ScopeRecord[Index].EndAddress)) {
				if (IS_TARGET_UNWIND(ExceptionRecord.ExceptionFlags)) {
					for (TargetIndex = 0;
						TargetIndex < ScopeTableCellPtr->Count;
						TargetIndex += 1) {
						if ((TargetPc >= ScopeTableCellPtr->ScopeRecord[TargetIndex].BeginAddress) &&
							(TargetPc < ScopeTableCellPtr->ScopeRecord[TargetIndex].EndAddress) &&
							(ScopeTableCellPtr->ScopeRecord[TargetIndex].JumpTarget ==
								ScopeTableCellPtr->ScopeRecord[Index].JumpTarget) &&
								(ScopeTableCellPtr->ScopeRecord[TargetIndex].HandlerAddress ==
									ScopeTableCellPtr->ScopeRecord[Index].HandlerAddress)) {
							break;
						}
					}

					if (TargetIndex != ScopeTableCellPtr->Count) {
						break;
					}
				}

				if (ScopeTableCellPtr->ScopeRecord[Index].JumpTarget != 0) {
					if ((TargetPc == ScopeTableCellPtr->ScopeRecord[Index].JumpTarget) &&
						(IS_TARGET_UNWIND(ExceptionRecord.ExceptionFlags))) {
						break;
					}
				}
				else {
					DispatcherContext.ScopeIndex = Index + 1;

					TerminationHandler = (PTERMINATION_HANDLER)
						(ScopeTable->ScopeRecord[Index].HandlerAddress + ImageBase);


					//TerminationHandler(TRUE, (PVOID)EstablisherFrame);
				}
			}
		}
	}

	return ExceptionContinueSearch;
}