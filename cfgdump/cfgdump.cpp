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
			dprintf(" %016llx | failed, can't load map bits\n", address);
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

DECLARE_API(cfgdmp)
{
	try
	{
		Arguments arguments(args);
		ULONGLONG offset = 0, cfgmap = 0, cfg = 0;
		HRESULT result;
		ULONG readed;

		if (!FindCFGMap(cfgmap))
			return;
		
		dprintf("\nCFG map: %llx\n\n", cfgmap);

		for (ULONG64 i = 0; i < 0x3FFFFF/*(0x7fffffffffffull >> 9) / 8*/; i++)
		{
			offset = cfgmap + (i * 8);

			result = g_DebugDataSpaces->ReadVirtual(offset, &cfg, sizeof(cfg), &readed);
			if (result != S_OK)
				continue;

			if (cfg == 0)
				continue;

			//dprintf("#%llx -> %llx\n", i << 9, cfg);

			for (auto a = 0; a < 8 * 8; a++)
			{
				auto base = i << 9;
				auto chkbit = 1ull << a;
				if ((cfg & chkbit) != 0ull)
				{
					//dprintf("%llx -> %llx -> %d -> %llx, %llx\n", base, base + (a * 8), a, cfg, (cfg & (1ull << a)));
					auto start = base + (a * 8);
					if ((a & 1) != 0)
						dprintf("%llx (16 bits)\n", start - 8);
					else
						dprintf("%llx (1 bit)\n", start);
				}
			}
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
