#pragma once

bool EmuReadNullTermString(uc_engine *uc, uint64_t address, std::string &str);
bool EmuReadNullTermUnicodeString(uc_engine *uc, uint64_t address, std::wstring &str);
uint64_t EmuReadReturnAddress(uc_engine *uc);

void EmuGetSystemTimeAsFileTime(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuGetCurrentThreadId(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuGetCurrentProcessId(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuQueryPerformanceCounter(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuLoadLibraryExW(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuGetProcAddress(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuGetModuleHandleA(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuGetLastError(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuInitializeCriticalSectionAndSpinCount(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuInitializeCriticalSectionEx(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuTlsAlloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuTlsSetValue(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuTlsFree(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuDeleteCriticalSection(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuLocalAlloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuRtlIsProcessorFeaturePresent(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

void EmuExAllocatePool(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuNtQuerySystemInformation(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuExFreePoolWithTag(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuIoAllocateMdl(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuMmProbeAndLockPages(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuMmMapLockedPagesSpecifyCache(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuKeQueryActiveProcessors(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuKeSetSystemAffinityThread(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuKeRevertToUserAffinityThread(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuMmUnlockPages(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuIoFreeMdl(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void EmuRtlGetVersion(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);