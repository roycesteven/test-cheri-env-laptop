// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT


#include <compartment.h>
#include <debug.hh>
#include <unwind.h>



/// Expose debugging features unconditionally for this compartment.
using Debug = ConditionalDebug<true, "Heap Buffer Over Read Compartment">;


/// Thread entry point.
int __cheri_compartment("heap-buffer-over-read") vuln1()
{
    volatile int ret = 0;
    CHERIOT_DURING{
        Debug::log("Running Buffer Over-read (C++)...");
        int* arr = new int[3];
        if (arr == nullptr)
        {
            Debug::log("Allocation failed!");
            return -1;
        }
        Debug::log("Array created, assigning values...");
        arr[0] = 10;
        arr[1] = 20;
        arr[2] = 30;
        Debug::log("Accessing arr[10] (out-of-bounds)...");
        int value = arr[10]; // Should fault
        Debug::log("Value: {} (This should not be printed)", value);
        delete[] arr;
    }
    CHERIOT_HANDLER{
        Debug::log("Heap Buffer Over Read: memory error detected in vuln1");
        ret = -1;
    }
    CHERIOT_END_HANDLER
    Debug::log("This line may not be reached if the program crashes.");
    return ret;
}