// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT
#include <compartment.h>
#include <debug.hh>
#include <unwind.h>

using Debug = ConditionalDebug<true, "Use After Free Compartment">;

int __cheri_compartment("use-after-free") vuln1()
{
    CHERIOT_DURING{
        Debug::log("Testing Use-After-Free (C++)...");
        int* ptr = new int;
        if (!ptr)
        {
            Debug::log("Allocation failed!");
            return 0;
        }
        *ptr = 123;
        Debug::log("ptr capability: {}", ptr);
        Debug::log("ptr points to memory with value: {}", *ptr);
        delete ptr;
        Debug::log("Memory has been freed.");
        *ptr = 456;
        Debug::log("Value is now: {} (this should not be printed)", *ptr);
    }
    CHERIOT_HANDLER{
        Debug::log("Use After Free: memory error detected in vuln1");
        return -1;
    } 
    CHERIOT_END_HANDLER

    return 0;
}
