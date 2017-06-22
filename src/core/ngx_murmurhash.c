
/*
 * Copyright (C) Austin Appleby
 */


#include <ngx_config.h>
#include <ngx_core.h>


uint32_t
ngx_murmur_hash2(u_char *data, size_t len)
{
    uint32_t  h, k;

    h = 0 ^ len;

    while (len >= 4) {
        k  = data[0];
        k |= data[1] << 8;
        k |= data[2] << 16;
        k |= data[3] << 24;

        k *= 0x5bd1e995;
        k ^= k >> 24;
        k *= 0x5bd1e995;

        h *= 0x5bd1e995;
        h ^= k;

        data += 4;
        len -= 4;
    }

    switch (len) {
    case 3:
        h ^= data[2] << 16;
        /* fall through */
    case 2:
        h ^= data[1] << 8;
        /* fall through */
    case 1:
        h ^= data[0];
        h *= 0x5bd1e995;
    }

    h ^= h >> 13;
    h *= 0x5bd1e995;
    h ^= h >> 15;

    return h;
}


uint64_t
ngx_murmur_hash2_64(u_char *data, size_t len, uint64_t seed)
{
    uint64_t  h, k;

    h = seed ^ len;

    while (len >= 8) {
        k  = data[0];
        k |= data[1] << 8;
        k |= data[2] << 16;
        k |= data[3] << 24;
        k |= (uint64_t)data[4] << 32;
        k |= (uint64_t)data[5] << 40;
        k |= (uint64_t)data[6] << 48;
        k |= (uint64_t)data[7] << 56;

        k *= 0xc6a4a7935bd1e995ull;
        k ^= k >> 47;
        k *= 0xc6a4a7935bd1e995ull;

        h ^= k;
        h *= 0xc6a4a7935bd1e995ull;

        data += 8;
        len -= 8;
    }

    switch (len) {
    case 7:
        h ^= (uint64_t)data[6] << 48;
        /* fall through */
    case 6:
        h ^= (uint64_t)data[5] << 40;
        /* fall through */
    case 5:
        h ^= (uint64_t)data[4] << 32;
        /* fall through */
    case 4:
        h ^= data[3] << 24;
        /* fall through */
    case 3:
        h ^= data[2] << 16;
        /* fall through */
    case 2:
        h ^= data[1] << 8;
        /* fall through */
    case 1:
        h ^= data[0];
        h *= 0xc6a4a7935bd1e995ull;
    }

    h ^= h >> 47;
    h *= 0xc6a4a7935bd1e995ull;
    h ^= h >> 47;

    return h;
}
