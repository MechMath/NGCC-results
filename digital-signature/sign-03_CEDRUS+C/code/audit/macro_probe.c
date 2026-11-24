#include <stdio.h>

#include "hash.h"
#include "params.h"

#define LOCAL_SPX_TREE_BITS (SPX_FULL_HEIGHT - SPX_TREE_HEIGHT + 1)
#define LOCAL_SPX_LEAF_BITS SPX_BOTTOM_TREE_HEIGHT

int main(void)
{
    const unsigned int shift = 32 - LOCAL_SPX_LEAF_BITS;
    printf("SPX_FULL_HEIGHT=%d SPX_D=%d SPX_TREE_HEIGHT=%d\n",
           SPX_FULL_HEIGHT, SPX_D, SPX_TREE_HEIGHT);
    printf("SPX_TREE_BITS=%d SPX_LEAF_BITS=%d shift=32-SPX_LEAF_BITS=%u "
           "effective_leaf_bits=%u effective_instances=%u\n",
           LOCAL_SPX_TREE_BITS, LOCAL_SPX_LEAF_BITS, shift, 32u - shift,
           1u << (32u - shift));
    return 0;
}
