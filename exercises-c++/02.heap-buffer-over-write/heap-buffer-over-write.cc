// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT
#include <compartment.h>
#include <debug.hh>
#include <unwind.h>

using Debug = ConditionalDebug<true, "Heap Buffer Over Write Compartment">;

int __cheri_compartment("heap-buffer-over-write") vuln1()
{
    volatile int ret = 0;
    CHERIOT_DURING{
    Debug::log("Testing Heap Buffer Over-write (C++)...");
    int* arr = nullptr;
    arr = new int[3];
    if (!arr) {
        Debug::log("Allocation failed!");
        return 0;
    }
    arr[0] = 1;
    arr[1] = 2;
    arr[2] = 3;
    Debug::log("Attempting to write arr[10] (out-of-bounds)...");
    arr[10] = 999;
    Debug::log("Write completed (this should not be printed).");
    Debug::log("Value of written element: {}.", arr[10]);
    delete[] arr;
    } CHERIOT_HANDLER {
        Debug::log("Heap Buffer Over Write: memory error detected in vuln1");
        ret = -1;
    }
    CHERIOT_END_HANDLER
    Debug::log("This line may not be reached if the program crashes.");
    return ret;
}
