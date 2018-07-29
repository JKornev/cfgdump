#include <Windows.h>
#include <imagehlp.h>
#include <wdbgexts.h>
#include <dbgeng.h>
#include "Helper.h"
#include <string>

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
const ULONGLONG MAX_CFGMAP64_SIZE = (0x400000000000ull >> 9) * sizeof(ULONGLONG);

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

void PrintCFGChunkHeader()
{
	dprintf("\n   Address          0123456789abcdef   0123456789abcdef   0123456789abcdef   0123456789abcdef\n");
}

void PrintCFGChunk(const MapChunk& chunk, bool clipped, bool& skipped)
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

		if (skipped)
		{
			dprintf("  ...\n");
			skipped = false;
		}

		dprintf(" %016llx", chunk.address + (i * 0x40));

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

void DumpCFGMapRange(ULONGLONG cfgmap, ULONGLONG address, ULONGLONG size, bool clipped)
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

	PrintCFGChunkHeader();

	bool skipped = false;
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

		PrintCFGChunk(chunk, clipped, skipped);
	}
}

bool FindCFGMap(ULONGLONG& cfgmap)
{
	ULONGLONG offset = 0;
	HRESULT result = g_DebugSymbols->GetOffsetByName("ntdll!LdrSystemDllInitBlock", &offset);
	if (result != S_OK)
		return false;

	offset += 0xB0;

	ULONG readed;
	result = g_DebugDataSpaces->ReadVirtual(offset, &cfgmap, sizeof(cfgmap), &readed);
	if (result != S_OK)
		return false;

	return true;
}

DECLARE_API(cfgrange)
{
	try
	{
		Arguments arguments(args);
		ULONGLONG cfgmap = 0, start = 0, size = 0;

		if (!FindCFGMap(cfgmap))
			return;
		
		std::string arg;
		if (!arguments.GetNext(arg))
			throw Exception("no address argument\n");

		start = std::stoll(arg, 0, 16);

		if (!arguments.GetNext(arg))
			throw Exception("no size argument\n");

		size = std::stoll(arg, 0, 16);

		DumpCFGMapRange(cfgmap, start, size, true);
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

const char* MemoryTypeToString(DWORD type)
{
	switch (type)
	{
	case MEM_IMAGE:
		return "MEM_IMAGE";
	case MEM_MAPPED:
		return "MEM_MAPPED";
	case MEM_PRIVATE:
		return "MEM_PRIVATE";
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
		return "MEM_COMMIT";
	case MEM_FREE:
		return "MEM_FREE";
	case MEM_RESERVE:
		return "MEM_RESERVE";
	default:
		break;
	}

	return "Unknown";
}

DECLARE_API(cfgdmp)
{
	try
	{
		Arguments arguments(args);
		ULONGLONG cfgmap;

		if (!FindCFGMap(cfgmap))
			return;

		auto cfgptr = cfgmap;
		auto cfgtop = cfgmap + MAX_CFGMAP64_SIZE;

		while (cfgptr < cfgtop)
		{
			MEMORY_BASIC_INFORMATION64 info;
			HRESULT result = g_DebugDataSpaces->QueryVirtual(cfgptr, &info);
			if (result != S_OK)
			{
				dprintf("Error, query virtual address %llx failed, code: %x\n", cfgptr, result);
				cfgptr += 0x1000;
				continue;
			}
			
			if (info.AllocationBase != cfgmap)
			{
				dprintf("Error, allocation base missmatched %016llx != %016llx\n", info.AllocationBase, cfgmap);
				break;
			}

			if (info.State != MEM_COMMIT || (info.Protect & PAGE_NOACCESS) != 0)
			{
				cfgptr += info.RegionSize;
				continue;
			}

			dprintf("\nCFG map region %016llx - %016llx (%llx)\n", info.BaseAddress, info.BaseAddress + info.RegionSize, info.RegionSize);

			auto address = ((cfgptr - cfgmap) << 9ull) / 8;
			auto size = (info.RegionSize / 8ull) * 0x200ull;
			dprintf("Region %016llx - %016llx (%llx)\n", address, address + size, size);

			DumpCFGMapRange(cfgmap, address, size, true);

			cfgptr += info.RegionSize;
		}

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
