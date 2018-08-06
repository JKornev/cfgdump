#include <Windows.h>
#include <imagehlp.h>
#include <wdbgexts.h>
#include <dbgeng.h>
#include "Helper.h"
#include <string>
#include <sstream>

#pragma comment(lib, "dbgeng.lib")

struct MapChunk {
	ULONGLONG address;
	union {
		unsigned long cfg32;
		unsigned long long cfg64;
	};
};

EXT_API_VERSION ExtApiVersion = { 1, 1, EXT_API_VERSION_NUMBER, 0 };

WINDBG_EXTENSION_APIS ExtensionApis = { 0 };

IDebugClient*      g_DebugClient = NULL;
IDebugSymbols3*    g_DebugSymbols = NULL;
IDebugDataSpaces2* g_DebugDataSpaces = NULL;

const ULONGLONG MAX_CFGMAP32_SIZE = (0x80000000ull >> 8) * sizeof(ULONG);
const ULONGLONG MAX_CFGMAP64_SIZE = (0x800000000000ull >> 9) * sizeof(ULONGLONG);

// --------------------------- 

VOID WDBGAPI WinDbgExtensionDllInit(PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT usMajorVersion, USHORT usMinorVersion)
{
	ExtensionApis = *lpExtensionApis;

	if (::DebugCreate(__uuidof(IDebugClient), (void**)&g_DebugClient) != S_OK)
	{
		dprintf("Acuqiring IDebugClient* Failled\n\n");
		return;
	}

	if (g_DebugClient->QueryInterface(__uuidof(IDebugSymbols3), (void**)&g_DebugSymbols) != S_OK)
	{
		dprintf("Acuqiring IDebugSymbols* Failled\n\n");
		return;
	}

	if (g_DebugClient->QueryInterface(__uuidof(IDebugDataSpaces2), (void**)&g_DebugDataSpaces) != S_OK)
	{
		dprintf("Acuqiring IDebugDataSpaces2* Failled\n\n");
		return;
	}
}

LPEXT_API_VERSION WDBGAPI ExtensionApiVersion(void)
{
	return &ExtApiVersion;
}

// --------------------------- 

const char* GetSpaces(unsigned int level)
{
	switch (level)
	{
	case 0:
		return "";
	case 1:
		return " ";
	case 2:
		return "  ";
	case 3:
		return "   ";
	case 4:
		return "    ";
	case 5:
		return "     ";
	case 6:
		return "      ";
	case 7:
		return "       ";
	default:
		break;
	}
	return     "        ";
}

void PrintCFGMapInfo(ULONGLONG cfgmap)
{
	dprintf("CFG Map64: %llx - %llx (%llx)\n\n", cfgmap, cfgmap + MAX_CFGMAP64_SIZE, MAX_CFGMAP64_SIZE);
}

void PrintCFGChunkHeader(unsigned int level)
{
	dprintf("\n%s  Address          0123456789abcdef   0123456789abcdef   0123456789abcdef   0123456789abcdef\n", GetSpaces(level));
}

void PrintCFGChunk(const MapChunk& chunk, unsigned int level, bool clipped, bool& skipped, bool& empty)
{
	auto bits = chunk.cfg64;

	for (auto i = 0; i < 8; i++)
	{
		if (clipped && (bits & 0xFF) == 0)
		{
			skipped = true;
			bits >>= 8;
			continue;
		}

		if (empty)
		{
			PrintCFGChunkHeader(level);
			empty = false;
		}

		if (skipped)
		{
			dprintf("%s ...\n", GetSpaces(level));
			skipped = false;
		}

		dprintf("%s%016llx", GetSpaces(level), chunk.address + (i * 0x40));

		for (auto a = 0; a < 4; a++)
		{
			if ((bits & 2) != 0)
				dprintf(" | ++++++++++++++++");
			else if ((bits & 1) != 0)
				dprintf(" | +...............");
			else
				dprintf(" | ................");

			bits >>= 2;
		}

		dprintf("\n");
	}
}

const char* MemoryTypeToString(DWORD type)
{
	switch (type)
	{
	case MEM_IMAGE:
		return "Image";
	case MEM_MAPPED:
		return "Mapped";
	case MEM_PRIVATE:
		return "Private";
	case 0:
		return "None";
	default:
		break;
	}

	return "Unknown";
}

const char* MemoryStateToString(DWORD state)
{
	switch (state)
	{
	case MEM_COMMIT:
		return "Commited";
	case MEM_FREE:
		return "Free";
	case MEM_RESERVE:
		return "Reserved";
	default:
		break;
	}

	return "Unknown";
}

std::string ConvertProtectionToString(DWORD protection)
{
	std::stringstream out;

	if (protection & PAGE_NOACCESS)
		out << "NoAccess";
	else if (protection & PAGE_READONLY)
		out << "ReadOnly";
	else if (protection & PAGE_READWRITE)
		out << "ReadWrite";
	else if (protection & PAGE_WRITECOPY)
		out << "WriteCopy";
	else if (protection & PAGE_EXECUTE)
		out << "Execute";
	else if (protection & PAGE_EXECUTE_READ)
		out << "ExecuteRead";
	else if (protection & PAGE_EXECUTE_READWRITE)
		out << "ExecuteReadWrite";
	else if (protection & PAGE_EXECUTE_WRITECOPY)
		out << "ExecuteWriteCopy";

	if (protection & PAGE_GUARD)
		out << "|Guard";
	if (protection & PAGE_NOCACHE)
		out << "|NoCache";
	if (protection & PAGE_WRITECOMBINE)
		out << "|WriteCombine";

	return out.str();
}

void GetMemoryInfoString(MEMORY_BASIC_INFORMATION64& info, char* buffer, size_t size)
{
	if (size >= 1)
		buffer[0] = '\0';

	if (info.Type != MEM_IMAGE)
		return;

	ULONGLONG base;
	HRESULT result = g_DebugSymbols->GetModuleByOffset(info.AllocationBase, 0, NULL, &base);
	if (result != S_OK)
		return;

	result = g_DebugSymbols->GetModuleNameString(DEBUG_MODNAME_IMAGE, 0, base, buffer, size, NULL);
	if (result != S_OK)
		return;
}

// --------------------------- 

ULONGLONG ConvertAddressToCfgMapAddress(ULONGLONG cfgmap, ULONGLONG address)
{
	return cfgmap + ((address >> 9) * 8);
}

bool LoadMapChunk(ULONGLONG cfgmap, ULONGLONG address, ULONGLONG size, MapChunk& chunk)
{
	ULONG readed;
	HRESULT result = g_DebugDataSpaces->ReadVirtual(
		ConvertAddressToCfgMapAddress(cfgmap, address),
		&chunk.cfg64,
		sizeof(chunk.cfg64),
		&readed
	);
	if (result != S_OK)
		return false;

	if (readed != sizeof(chunk.cfg64))
		return false;

	chunk.address = address;
	return true;
}

bool IsMemoryFree(ULONGLONG address, ULONGLONG size)
{
	MEMORY_BASIC_INFORMATION64 info;
	auto end = address + size;

	do
	{
		HRESULT result = g_DebugDataSpaces->QueryVirtual(address, &info);
		if (result != S_OK)
			return false;


	}
	while (info.BaseAddress);

	return false;
}

void FindCFGMap(ULONGLONG& cfgmap)
{
	ULONGLONG offset = 0;
	HRESULT result = g_DebugSymbols->GetOffsetByName("ntdll!LdrSystemDllInitBlock", &offset);
	if (result != S_OK)
		throw Exception("can't get address of ntdll!LdrSystemDllInitBlock");

	for (auto i = 0; i < 20; i++)
	{
		offset += 0x10;

		ULONG readed;
		result = g_DebugDataSpaces->ReadVirtual(offset, &cfgmap, sizeof(cfgmap), &readed);
		if (result != S_OK)
			continue;

		MEMORY_BASIC_INFORMATION64 info;
		HRESULT result = g_DebugDataSpaces->QueryVirtual(cfgmap, &info);
		if (result != S_OK)
			continue;

		if (cfgmap == info.AllocationBase && info.Type == MEM_MAPPED)
			return;
	}
	
	throw Exception("can't find CFG map");
}

// --------------------------- 

bool DumpCFGMapRange(ULONGLONG cfgmap, ULONGLONG address, ULONGLONG size, unsigned int level, bool clipped)
{
	//   Address          0123456789abcdef   0123456789abcdef   0123456789abcdef   0123456789abcdef
	// 0000000003fce800 | ................ | ++++++++++++++++ | ................ | ................
	// 0000000003fce840 | ................ | +............... | ................ | ................
	// 0000000003fce880 | ................ | ++++++++++++++++ | ................ | ................
	// 0000000003fce8c0 | ................ | +............... | ................ | ................
	// 0000000003fce900 | ................ | ++++++++++++++++ | ................ | ................
	// 0000000003fce940 | ................ | +............... | ................ | ................
	// 0000000003fce980 | ................ | ++++++++++++++++ | ................ | ................
	// 0000000003fce9c0 | ................ | +............... | ................ | ................
	// ...
	// 0000000003fce080 | ................ | ++++++++++++++++ | ................ | ................
	// ...

	const auto chunkBlockSize = 0x200ul;

	auto start = address - (address % chunkBlockSize);
	auto delta = (address + size) - start;
	auto chunks = (delta / chunkBlockSize) + (delta % chunkBlockSize ? 1 : 0);

	bool skipped = false;
	bool empty = true;
	for (auto i = 0ull; i < chunks; i++)
	{
		MapChunk chunk;
		auto address = start + (i * chunkBlockSize);

		if (!LoadMapChunk(cfgmap, address, chunkBlockSize, chunk))
		{
			//TODO: improve it, not need to print error message for each chunk
			//dprintf(" %016llx | failed, can't load map bits\n", address);
			continue;
		}

		PrintCFGChunk(chunk, level, clipped, skipped, empty);
	}

	return !empty;
}

DECLARE_API(cfgrange)
{
	try
	{
		Arguments arguments(args);
		ULONGLONG cfgmap = 0, start = 0, size = 0;

		FindCFGMap(cfgmap);
		
		std::string arg;
		if (!arguments.GetNext(arg))
			throw Exception("no address argument\n");

		start = std::stoll(arg, 0, 16);

		if (!arguments.GetNext(arg))
			size = 1;
		else
			size = std::stoll(arg, 0, 16);

		DumpCFGMapRange(cfgmap, start, size, 1, true);
	}
	catch (Exception& e)
	{
		dprintf("Error: %s\n", e.What());
	}
	catch (std::exception& e)
	{
		dprintf("STDError: %s\n", e.what());
	}
}

// --------------------------- 

void DumpMemoryInCFGRegion(ULONGLONG cfgmap, ULONGLONG address, ULONGLONG size, bool clipped)
{
	auto ptr = address;
	auto top = address + size;

	while (ptr < top)
	{
		MEMORY_BASIC_INFORMATION64 info;
		HRESULT result = g_DebugDataSpaces->QueryVirtual(ptr, &info);
		if (result != S_OK)
		{
			dprintf("Warning: query virtual address %llx failed, code: %x\n", ptr, result);
			ptr += 0x1000;
			continue;
		}

		auto range = info.BaseAddress + info.RegionSize - ptr;

		if (ptr + range > top)
			range = top - ptr;

		dprintf("  Region: %llx - %llx (%llx), %s, %s\n", 
			ptr,
			ptr + range,
			range,
			MemoryStateToString(info.State),
			MemoryTypeToString(info.Type)
		);
		
		if (!DumpCFGMapRange(cfgmap, ptr, range, 3, clipped))
			dprintf("      without cfg bits\n");

		dprintf("\n");
		ptr += range;
	}
}

void DumpFullCFGMap(ULONGLONG cfgmap)
{
	auto cfgptr = cfgmap;
	auto cfgtop = cfgmap + MAX_CFGMAP64_SIZE;

	dprintf("\n");

	PrintCFGMapInfo(cfgmap);

	while (cfgptr < cfgtop)
	{
		MEMORY_BASIC_INFORMATION64 info;
		HRESULT result = g_DebugDataSpaces->QueryVirtual(cfgptr, &info);
		if (result != S_OK)
		{
			dprintf("Warning: query virtual address %llx failed, code: %x\n", cfgptr, result);
			cfgptr += 0x1000;
			continue;
		}

		if (info.AllocationBase != cfgmap)
		{
			dprintf("Warning: allocation base missmatched %016llx != %016llx\n", info.AllocationBase, cfgmap);
			break;
		}

		if (info.State != MEM_COMMIT || (info.Protect & PAGE_NOACCESS) != 0)
		{
			//dprintf("Skip no access: %016llx, %016llx\n", cfgptr, info.RegionSize);
			cfgptr += info.RegionSize;
			continue;
		}

		auto address = ((cfgptr - cfgmap) << 9ull) / 8;
		auto size = (info.RegionSize / 8ull) * 0x200ull;

		dprintf(" CFG Region: %llx - %llx (%llx)\n\n", address, address + size, size);

		DumpMemoryInCFGRegion(cfgmap, address, size, true);

		cfgptr += info.RegionSize;
		dprintf("\n");
	}
}

DECLARE_API(cfgdump)
{
	try
	{
		ULONGLONG cfgmap;
		FindCFGMap(cfgmap);
		DumpFullCFGMap(cfgmap);
	}
	catch (Exception& e)
	{
		dprintf("Error: %s\n", e.What());
	}
	catch (std::exception& e)
	{
		dprintf("STDError: %s\n", e.what());
	}
}

// --------------------------- 

const char* GetCFGRangeState(ULONGLONG cfgmap, ULONGLONG address, ULONGLONG size)
{
	const auto chunkBlockSize = 0x200ul;

	auto start = address - (address % chunkBlockSize);
	auto delta = (address + size) - start;
	auto chunks = (delta / chunkBlockSize) + (delta % chunkBlockSize ? 1 : 0);
	bool failed = false;

	for (auto i = 0ull; i < chunks; i++)
	{
		MapChunk chunk;
		auto address = start + (i * chunkBlockSize);

		if (!LoadMapChunk(cfgmap, address, chunkBlockSize, chunk))
		{
			failed = true;
			continue;
		}
		
		if (chunk.cfg64)
			return "+";
	}

	return (failed ? "?" : " ");
}

void DumpMemoryMapInCFGRegion(ULONGLONG cfgmap, ULONGLONG address, ULONGLONG size)
{
	auto ptr = address;
	auto top = address + size;

	dprintf("   Start              End                Size           CFGbits Type       State      Protection\n");

	while (ptr < top)
	{
		MEMORY_BASIC_INFORMATION64 info;
		HRESULT result = g_DebugDataSpaces->QueryVirtual(ptr, &info);
		if (result != S_OK)
		{
			dprintf("Warning: query virtual address %llx failed, code: %x\n", ptr, result);
			ptr += 0x1000;
			continue;
		}

		auto range = info.BaseAddress + info.RegionSize - ptr;

		if (ptr + range > top)
			range = top - ptr;

		char memory[MAX_PATH];
		GetMemoryInfoString(info, memory, sizeof(memory));

		dprintf("  %016llx | %016llx | %016llx | %s | %-8s | %-8s | %-25s %s\n",
			ptr,
			ptr + range,
			range,
			GetCFGRangeState(cfgmap, ptr, range),
			MemoryTypeToString(info.Type),
			MemoryStateToString(info.State),
			ConvertProtectionToString(info.Protect).c_str(),
			memory
		);

		ptr += range;
	}
}

void DumpCFGCoveredMemory(ULONGLONG cfgmap)
{
	auto cfgptr = cfgmap;
	auto cfgtop = cfgmap + MAX_CFGMAP64_SIZE;

	dprintf("\n");

	PrintCFGMapInfo(cfgmap);

	while (cfgptr < cfgtop)
	{
		MEMORY_BASIC_INFORMATION64 info;
		HRESULT result = g_DebugDataSpaces->QueryVirtual(cfgptr, &info);
		if (result != S_OK)
		{
			dprintf("Warning: query virtual address %llx failed, code: %x\n", cfgptr, result);
			cfgptr += 0x1000;
			continue;
		}

		if (info.AllocationBase != cfgmap)
		{
			dprintf("Warning: allocation base missmatched %016llx != %016llx\n", info.AllocationBase, cfgmap);
			break;
		}

		if (info.State != MEM_COMMIT || (info.Protect & PAGE_NOACCESS) != 0)
		{
			//dprintf("Skip no access: %016llx, %016llx\n", cfgptr, info.RegionSize);
			cfgptr += info.RegionSize;
			continue;
		}

		auto address = ((cfgptr - cfgmap) << 9ull) / 8;
		auto size = (info.RegionSize / 8ull) * 0x200ull;

		dprintf(" CFG Region: %llx - %llx (%llx)\n\n", address, address + size, size);

		DumpMemoryMapInCFGRegion(cfgmap, address, size);

		cfgptr += info.RegionSize;
		dprintf("\n");
	}
}

DECLARE_API(cfgcover)
{
	try
	{
		ULONGLONG cfgmap;
		FindCFGMap(cfgmap);
		DumpCFGCoveredMemory(cfgmap);
	}
	catch (Exception& e)
	{
		dprintf("Error: %s\n", e.What());
	}
	catch (std::exception& e)
	{
		dprintf("STDError: %s\n", e.what());
	}
}