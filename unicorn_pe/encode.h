#pragma once

void ANSIToUnicode(const std::string &str, std::wstring &out);
void UnicodeToANSI(const std::wstring &str, std::string &out);
void UnicodeToUTF8(const std::wstring &str, std::string &out);
void UTF8ToUnicode(const std::string &str, std::wstring &out);