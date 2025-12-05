// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT
#include <compartment.h>
#include <debug.hh>
#include <unwind.h>

using Debug = ConditionalDebug<true, "Heap Buffer Under Write Compartment">;

int __cheri_compartment("heap-buffer-under-write") vuln1()
{
    int ret = 0;
    CHERIOT_DURING{
    Debug::log("Testing Heap Buffer Under-write (C++)...");
    int* arr = new int[3];
    if (!arr)
    {
        Debug::log("Allocation failed!");
        return 0;
    }
    arr[0] = 10;
    arr[1] = 20;
    arr[2] = 30;
    Debug::log("Attempting under-write arr[-1] = 999 ...");
    arr[-1] = 999;
    Debug::log("Under-write completed (this should not be printed).");
    Debug::log("Inserted element: {}.", arr[-1]);
    delete[] arr;
    }
    CHERIOT_HANDLER{
        Debug::log("Heap Buffer Under Write: memory error detected in vuln1");
        ret = -1;
    }
    CHERIOT_END_HANDLER
    Debug::log("This line may not be reached if the program crashes.");
    return ret;
}
