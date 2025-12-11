#include <compartment.h>
#include <debug.h>
#include <unwind.h>

#define DEBUG_CONTEXT "Type Confusion Compartment"

const char hello[] = "Hello World!";

union long_ptr {
    long l;
    const char *ptr;
} lp = { .ptr = hello };

void inc_long_ptr(union long_ptr *lpp) {
    lpp->l++;
}

__cheri_compartment("type-confusion") int vuln1(void)
{
    volatile int ret = 0;
    CHERIOT_DURING{
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Testing Type confusion (C)...");

    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Before inc_long_ptr: lp.ptr = {}", (char*)lp.ptr);
    inc_long_ptr(&lp);
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "After inc_long_ptr: lp.ptr = {}", (char*)lp.ptr);
    }
    CHERIOT_HANDLER{
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "Type Confusion: memory error detected in vuln1");
    ret = -1;
    }
    CHERIOT_END_HANDLER 
    CHERIOT_DEBUG_LOG(DEBUG_CONTEXT, "This line may not be reached if the program crashes.");
    return  ret;
}
