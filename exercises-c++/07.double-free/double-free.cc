// Diagnostics for double-free behavior
// SPDX-License-Identifier: MIT

#include <errno.h>
#include <compartment.h>
#include <debug.hh>
#include <unwind.h>

using Debug = ConditionalDebug<true, "Double Compartment">;


__cheri_compartment("double-free") int vuln1(void)
{
    Debug::log("Testing Double Free...");

    int *ptr = (int*)malloc(sizeof(int));
    if (!ptr) { Debug::log( "malloc returned NULL"); return 0; }
    *ptr = 42;

    int ret = 0;

    int err = free(ptr);
    if (err == -EINVAL) {
        Debug::log( "Caught double free error: {}", err);
        ret = -1;
    } 
    else if (err == -ENOTENOUGHSTACK) {
        Debug::log( "Caught stack overflow error: {}", err);
        ret = -1;
    }
    Debug::log("After first free");

    err = heap_free(MALLOC_CAPABILITY,ptr);
    if (err == -EINVAL) {
        Debug::log( "Caught double free error: {}", err);
        ret = -1;
    } 
    else if (err == -ENOTENOUGHSTACK) {
        Debug::log( "Caught stack overflow error: {}", err);
        ret = -1;
    }
    Debug::log("After second free");
    Debug::log("This line may not be reached if the program crashes.");
    return ret;
}