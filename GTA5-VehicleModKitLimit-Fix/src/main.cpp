#include "hooking.h"

struct PatternPair
{
	std::string_view pattern;
	int offset;
};

static uint16_t* _vehicleModKitArray;
int NUM_MODKIT_INDICES;
void TomlShit()
{
	NUM_MODKIT_INDICES = GetPrivateProfileIntW(L"ModKitLimitPatch", L"ModkitIDs", -1, L".\\ModKitLimitExtender.toml");
	NUM_MODKIT_INDICES = NUM_MODKIT_INDICES <= 0 ? 0x400 : NUM_MODKIT_INDICES;
}

void RelocateRelative(std::initializer_list<PatternPair> list)
{
	void* oldAddress = nullptr;

	for (auto& entry : list)
	{
		auto location = hook::get_pattern<int32_t>(entry.pattern, entry.offset);

		if (!oldAddress)
		{
			oldAddress = hook::get_address<void*>(location);
		}

		auto target = hook::get_address<void*>(location);
		assert(target == oldAddress);

		hook::put<int32_t>(location, (intptr_t)_vehicleModKitArray - (intptr_t)location - 4);
	}
}

void RelocateAbsolute(std::initializer_list<PatternPair> list)
{
	int32_t oldAddress = 0;

	for (auto& entry : list)
	{
		auto location = hook::get_pattern<int32_t>(entry.pattern, entry.offset);

		if (!oldAddress)
		{
			oldAddress = *location;
		}

		auto target = *location;
		assert(target == oldAddress);

		hook::put<int32_t>(location, (intptr_t)_vehicleModKitArray - uintptr_t(GetModuleHandleW(nullptr)));
	}
}

// https://github.com/citizenfx/fivem/blob/master/code/components/gta-streaming-five/src/ModKitIdRelocation.cpp
void initialize()
	{
		_vehicleModKitArray = (uint16_t*)hook::AllocateStubMemory(sizeof(uint16_t) * NUM_MODKIT_INDICES);
RelocateRelative(
	{ { "66 3B F0 73 ? 48 8D", 8 },
	{ "66 41 3B C0 73 ? 48 8D", 9 },
	{ "45 33 C0 4C 8D 0D ? ? ? ? B9", 6 },
	{ "B8 FF FF 00 00 48 8D 3D", 8 },
	{ "7D ? 41 BC FF FF 00 00 4C 8D 3D", 11 } });
RelocateAbsolute(
	{ { "66 3B D1 73 ? 8B C2", 11 },
	{ "66 39 4B 2A 73 ? 0F", 14 } });
hook::nop(hook::get_pattern("66 3B F0 73 ? 48 8D", 0), 5);
hook::nop(hook::get_pattern("66 41 3B C0 73 ? 48 8D", 0), 6);
hook::nop(hook::get_pattern("66 3B D1 73 ? 8B C2", 0), 5);
hook::nop(hook::get_pattern("66 39 4B 2A 73 ? 0F", 0), 6);
hook::nop(hook::get_pattern("41 81 F8 00 04 00 00 7C", 0), 9);

{
	auto location = hook::get_pattern("B8 FF FF 00 00 48 8D 3D", 13);
	hook::put<int32_t>(location, NUM_MODKIT_INDICES);
}
	};

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) 
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		TomlShit();
		initialize();
		break;
	}
	return TRUE;  
}