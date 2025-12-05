// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.h>
#include <unwind.h>
#include <stdlib.h>


#define DEBUG_CONTEXT "Use After Free Compartment"

/// Thread entry point.
__cheri_compartment("use-after-free") int vuln1()
{
    int ret = 0;
    CHERIOT_DURING{
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Use-After-Free (C)...");
    int* ptr = (int*)malloc(sizeof(int));
    if (ptr == NULL) {return 0;}
    *ptr = 123;
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "ptr points to memory with value: {}", *ptr);

    free(ptr);
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Memory has been freed.");

    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Attempting to dereference dangling pointer... ");
    *ptr = 456;
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Value is now: {}", *ptr);
    }
    CHERIOT_HANDLER{
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Use After Free: memory error detected in vuln1");
    ret = -1;
    }
    CHERIOT_END_HANDLER 

    return ret;
}
