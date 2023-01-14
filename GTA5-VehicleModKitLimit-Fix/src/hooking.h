#pragma once

#include "..\dependency\Hooking.Patterns\Hooking.Patterns.h"
#include <Windows.h>

namespace hook
{
	template<typename ValueType, typename AddressType>
	inline void put(AddressType address, ValueType value)
	{
		DWORD oldProtect;
		VirtualProtect((void*)address, sizeof(value), PAGE_EXECUTE_READWRITE, &oldProtect);

		memcpy((void*)address, &value, sizeof(value));

		VirtualProtect((void*)address, sizeof(value), oldProtect, &oldProtect);

		FlushInstructionCache(GetCurrentProcess(), (void*)address, sizeof(value));
	}

	template<typename AddressType>
	inline void nop(AddressType address, size_t length)
	{

		DWORD oldProtect;
		VirtualProtect((void*)address, length, PAGE_EXECUTE_READWRITE, &oldProtect);

		memset((void*)address, 0x90, length);

		VirtualProtect((void*)address, length, oldProtect, &oldProtect);
		FlushInstructionCache(GetCurrentProcess(), (void*)address, length);
	}

	void* AllocateStubMemory(size_t size);

	template<typename T, typename TAddr>
	inline T get_address(TAddr address)
	{
		intptr_t target = *(int32_t*)(uintptr_t(address));
		target += (uintptr_t(address) + sizeof(int32_t));

		return (T)target;
	}
}