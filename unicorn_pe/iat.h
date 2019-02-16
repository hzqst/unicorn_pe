#pragma once

#include <string>
#include <set>
#include <vector>
#include <unordered_map>
#include <windows.h>

typedef struct _vmpstr_dec {
	_vmpstr_dec(int a, int b, int c) : insn_rva(a), encrypt_string_rva(b), call_rva(c){

	}
	int insn_rva;
	int encrypt_string_rva;
	int call_rva;
	std::vector<char> bytes;
}vmpstr_dec;

typedef struct _rebuildiat_api {
	_rebuildiat_api() {
		funcname_rva = 0;
		ord = 0;
	}
	std::string funcname;
	int funcname_rva;
	ULONG64 ord;
	std::set<int> rvaFF15;
}rebuildiat_api;

typedef struct _rebuildiat_apis {
	_rebuildiat_apis() {
		dllname_rva = 0;
	}
	std::vector<rebuildiat_api> apis;
	int dllname_rva;
	int othunk_rva;
	int thunk_rva;
}rebuildiat_apis;

using rebuildiat_dlls = std::unordered_map<std::string, rebuildiat_apis *>;