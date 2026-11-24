#include <stdint.h>

#include "params.h"
#include "utils.h"

void set_chain_addr(uint32_t addr[8], uint32_t chain)
{
    u32_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_CHAIN_ADDR - 3], chain);
}
