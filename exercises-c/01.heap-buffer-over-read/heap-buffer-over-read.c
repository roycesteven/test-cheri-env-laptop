// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment.h>
#include <debug.h>
#include <unwind.h>
#include <stdlib.h>


#define DEBUG_CONTEXT "Heap Buffer Over Read Compartment"

/// Thread entry point.
__cheri_compartment("heap-buffer-over-read") int vuln1()
{
    int ret = 0;
    CHERIOT_DURING{
    int* arr = (int*)malloc(3 * sizeof(int));
    if (arr == NULL) {
         CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "malloc failed");
        return 0;} // Always check for malloc failure
    arr[0] = 10;
    arr[1] = 20;
    arr[2] = 30;

    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Buffer Over-read (C)...");

    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Accessing arr[10]... ");
    int value = arr[10]; 
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Value: {} (This should not be printed)", value);

    free(arr);

    }
    CHERIOT_HANDLER{
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Heap Buffer Over Read: memory error detected in vuln1");
    ret = -1;
    }
    CHERIOT_END_HANDLER
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "This line may not be reached if the program crashes.");

    return ret;
}
