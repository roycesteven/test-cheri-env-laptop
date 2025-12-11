// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.h>
#include <unwind.h>

#define DEBUG_CONTEXT "OOB Pointer Arithmetic Compartment"

__cheri_compartment("oob-pointer-arithmetic") int vuln1(void)
{  
    volatile int ret = 0;
    CHERIOT_DURING{
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Out-Of-Bounds Pointer Arithmetic (C)...");
    int arr[4] = {100, 200, 300, 400};
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Array base: {}", (uintptr_t)arr);

    /* Make a pointer well past the end via arithmetic */
    int *p = arr + 10; // pointer now points far beyond arr
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Pointer moved to arr + 10: {}", (uintptr_t)p);

    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Dereferencing OOB pointer ...");
    int val = *p; // out-of-bounds read (or write) via pointer arithmetic
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Read value: {} (this should not be printed)", val);
    }
    CHERIOT_HANDLER{
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "OOB Pointer Arithmetic: memory error detected in vuln1");
    ret = -1;
    }
    CHERIOT_END_HANDLER 
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "This line may not be reached if the program crashes.");
    return ret;
}
