#include <stdint.h>
#include <string.h>

#include "params.h"
#include "utils.h"

void set_layer_addr(uint32_t addr[8], uint32_t layer)
{
    ((unsigned char *)addr)[SPX_OFFSET_LAYER] = layer;
}

void set_tree_addr(uint32_t addr[8], uint64_t tree)
{
    ull_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_TREE], 8, tree);
}

void set_type(uint32_t addr[8], uint32_t type)
{
    ((unsigned char *)addr)[SPX_OFFSET_TYPE] = type;
}

void copy_subtree_addr(uint32_t out[8], const uint32_t in[8])
{
    memcpy(out, in, SPX_OFFSET_TREE + 8);
}

void set_keypair_addr(uint32_t addr[8], uint32_t keypair)
{
#if SPX_BOTTOM_TREE_HEIGHT > 8
    ((unsigned char *)addr)[SPX_OFFSET_KP_ADDR2] = keypair >> 8;
#endif
    ((unsigned char *)addr)[SPX_OFFSET_KP_ADDR1] = keypair;
}

void copy_keypair_addr(uint32_t out[8], const uint32_t in[8])
{
    memcpy(out, in, SPX_OFFSET_TREE + 8);
#if SPX_BOTTOM_TREE_HEIGHT > 8
    ((unsigned char *)out)[SPX_OFFSET_KP_ADDR2] =
        ((unsigned char *)in)[SPX_OFFSET_KP_ADDR2];
#endif
    ((unsigned char *)out)[SPX_OFFSET_KP_ADDR1] =
        ((unsigned char *)in)[SPX_OFFSET_KP_ADDR1];
}

void set_chain_addr(uint32_t addr[8], uint32_t chain)
{
    u32_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_CHAIN_ADDR - 3], chain);
}

void set_hash_addr(uint32_t addr[8], uint32_t hash)
{
    ((unsigned char *)addr)[SPX_OFFSET_HASH_ADDR] = hash;
}

void set_tree_height(uint32_t addr[8], uint32_t tree_height)
{
    ((unsigned char *)addr)[SPX_OFFSET_TREE_HGT] = tree_height;
}

void set_tree_index(uint32_t addr[8], uint32_t tree_index)
{
    u32_to_bytes(&((unsigned char *)addr)[SPX_OFFSET_TREE_INDEX], tree_index);
}
