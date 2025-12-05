// Diagnostics for double-free behavior
// SPDX-License-Identifier: MIT

#include <errno.h>
#include <compartment.h>
#include <debug.h>
#include <unwind.h>
#include <stdlib.h>

#define DEBUG_CONTEXT "Double Free Compartment"

__cheri_compartment("double-free") int vuln1(void)
{
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Double Free...");

    int *ptr = (int*)malloc(sizeof(int));
    if (!ptr) { CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "malloc returned NULL"); return 0; }
    *ptr = 42;

    int *ptr2 = ptr;

    int ret = 0;

    int err = heap_free(MALLOC_CAPABILITY,ptr);
    if (err == -EINVAL) {
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Caught double free error: {}", err);
    } 
    else if (err == -ENOTENOUGHSTACK) {
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Caught stack overflow error: {}", err);
    }
    

    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "After first free");

    err = heap_free(MALLOC_CAPABILITY, ptr2);
    if (err == -EINVAL) {
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Caught double free error: {}", err);
    } 
    else if (err == -ENOTENOUGHSTACK) {
        CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Caught stack overflow error: {}", err);
    }

    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "After second free");

    return ret;
}