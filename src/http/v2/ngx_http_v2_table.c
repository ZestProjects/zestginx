
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_V2_TABLE_SIZE  4096


static ngx_int_t ngx_http_v2_table_account(ngx_http_v2_connection_t *h2c,
    size_t size);


static ngx_http_v2_header_t  ngx_http_v2_static_table[] = {
    { ngx_string(":authority"), ngx_string("") },
    { ngx_string(":method"), ngx_string("GET") },
    { ngx_string(":method"), ngx_string("POST") },
    { ngx_string(":path"), ngx_string("/") },
    { ngx_string(":path"), ngx_string("/index.html") },
    { ngx_string(":scheme"), ngx_string("http") },
    { ngx_string(":scheme"), ngx_string("https") },
    { ngx_string(":status"), ngx_string("200") },
    { ngx_string(":status"), ngx_string("204") },
    { ngx_string(":status"), ngx_string("206") },
    { ngx_string(":status"), ngx_string("304") },
    { ngx_string(":status"), ngx_string("400") },
    { ngx_string(":status"), ngx_string("404") },
    { ngx_string(":status"), ngx_string("500") },
    { ngx_string("accept-charset"), ngx_string("") },
    { ngx_string("accept-encoding"), ngx_string("gzip, deflate") },
    { ngx_string("accept-language"), ngx_string("") },
    { ngx_string("accept-ranges"), ngx_string("") },
    { ngx_string("accept"), ngx_string("") },
    { ngx_string("access-control-allow-origin"), ngx_string("") },
    { ngx_string("age"), ngx_string("") },
    { ngx_string("allow"), ngx_string("") },
    { ngx_string("authorization"), ngx_string("") },
    { ngx_string("cache-control"), ngx_string("") },
    { ngx_string("content-disposition"), ngx_string("") },
    { ngx_string("content-encoding"), ngx_string("") },
    { ngx_string("content-language"), ngx_string("") },
    { ngx_string("content-length"), ngx_string("") },
    { ngx_string("content-location"), ngx_string("") },
    { ngx_string("content-range"), ngx_string("") },
    { ngx_string("content-type"), ngx_string("") },
    { ngx_string("cookie"), ngx_string("") },
    { ngx_string("date"), ngx_string("") },
    { ngx_string("etag"), ngx_string("") },
    { ngx_string("expect"), ngx_string("") },
    { ngx_string("expires"), ngx_string("") },
    { ngx_string("from"), ngx_string("") },
    { ngx_string("host"), ngx_string("") },
    { ngx_string("if-match"), ngx_string("") },
    { ngx_string("if-modified-since"), ngx_string("") },
    { ngx_string("if-none-match"), ngx_string("") },
    { ngx_string("if-range"), ngx_string("") },
    { ngx_string("if-unmodified-since"), ngx_string("") },
    { ngx_string("last-modified"), ngx_string("") },
    { ngx_string("link"), ngx_string("") },
    { ngx_string("location"), ngx_string("") },
    { ngx_string("max-forwards"), ngx_string("") },
    { ngx_string("proxy-authenticate"), ngx_string("") },
    { ngx_string("proxy-authorization"), ngx_string("") },
    { ngx_string("range"), ngx_string("") },
    { ngx_string("referer"), ngx_string("") },
    { ngx_string("refresh"), ngx_string("") },
    { ngx_string("retry-after"), ngx_string("") },
    { ngx_string("server"), ngx_string("") },
    { ngx_string("set-cookie"), ngx_string("") },
    { ngx_string("strict-transport-security"), ngx_string("") },
    { ngx_string("transfer-encoding"), ngx_string("") },
    { ngx_string("user-agent"), ngx_string("") },
    { ngx_string("vary"), ngx_string("") },
    { ngx_string("via"), ngx_string("") },
    { ngx_string("www-authenticate"), ngx_string("") },
};

#define NGX_HTTP_V2_STATIC_TABLE_ENTRIES                                      \
    (sizeof(ngx_http_v2_static_table)                                         \
     / sizeof(ngx_http_v2_header_t))


ngx_str_t *
ngx_http_v2_get_static_name(ngx_uint_t index)
{
    return &ngx_http_v2_static_table[index - 1].name;
}


ngx_str_t *
ngx_http_v2_get_static_value(ngx_uint_t index)
{
    return &ngx_http_v2_static_table[index - 1].value;
}


ngx_int_t
ngx_http_v2_get_indexed_header(ngx_http_v2_connection_t *h2c, ngx_uint_t index,
    ngx_uint_t name_only)
{
    u_char                *p;
    size_t                 rest;
    ngx_http_v2_header_t  *entry;

    if (index == 0) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent invalid hpack table index 0");
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 get indexed %s: %ui",
                   name_only ? "name" : "header", index);

    index--;

    if (index < NGX_HTTP_V2_STATIC_TABLE_ENTRIES) {
        h2c->state.header = ngx_http_v2_static_table[index];
        return NGX_OK;
    }

    index -= NGX_HTTP_V2_STATIC_TABLE_ENTRIES;

    if (index < h2c->hpack.added - h2c->hpack.deleted) {
        index = (h2c->hpack.added - index - 1) % h2c->hpack.allocated;
        entry = h2c->hpack.entries[index];

        p = ngx_pnalloc(h2c->state.pool, entry->name.len + 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        h2c->state.header.name.len = entry->name.len;
        h2c->state.header.name.data = p;

        rest = h2c->hpack.storage + NGX_HTTP_V2_TABLE_SIZE - entry->name.data;

        if (entry->name.len > rest) {
            p = ngx_cpymem(p, entry->name.data, rest);
            p = ngx_cpymem(p, h2c->hpack.storage, entry->name.len - rest);

        } else {
            p = ngx_cpymem(p, entry->name.data, entry->name.len);
        }

        *p = '\0';

        if (name_only) {
            return NGX_OK;
        }

        p = ngx_pnalloc(h2c->state.pool, entry->value.len + 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        h2c->state.header.value.len = entry->value.len;
        h2c->state.header.value.data = p;

        rest = h2c->hpack.storage + NGX_HTTP_V2_TABLE_SIZE - entry->value.data;

        if (entry->value.len > rest) {
            p = ngx_cpymem(p, entry->value.data, rest);
            p = ngx_cpymem(p, h2c->hpack.storage, entry->value.len - rest);

        } else {
            p = ngx_cpymem(p, entry->value.data, entry->value.len);
        }

        *p = '\0';

        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                  "client sent out of bound hpack table index: %ui", index);

    return NGX_ERROR;
}


ngx_int_t
ngx_http_v2_add_header(ngx_http_v2_connection_t *h2c,
    ngx_http_v2_header_t *header)
{
    size_t                 avail;
    ngx_uint_t             index;
    ngx_http_v2_header_t  *entry, **entries;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 table add: \"%V: %V\"",
                   &header->name, &header->value);

    if (h2c->hpack.entries == NULL) {
        h2c->hpack.allocated = 64;
        h2c->hpack.size = NGX_HTTP_V2_TABLE_SIZE;
        h2c->hpack.free = NGX_HTTP_V2_TABLE_SIZE;

        h2c->hpack.entries = ngx_palloc(h2c->connection->pool,
                                        sizeof(ngx_http_v2_header_t *)
                                        * h2c->hpack.allocated);
        if (h2c->hpack.entries == NULL) {
            return NGX_ERROR;
        }

        h2c->hpack.storage = ngx_palloc(h2c->connection->pool,
                                        h2c->hpack.free);
        if (h2c->hpack.storage == NULL) {
            return NGX_ERROR;
        }

        h2c->hpack.pos = h2c->hpack.storage;
    }

    if (ngx_http_v2_table_account(h2c, header->name.len + header->value.len)
        != NGX_OK)
    {
        return NGX_OK;
    }

    if (h2c->hpack.reused == h2c->hpack.deleted) {
        entry = ngx_palloc(h2c->connection->pool, sizeof(ngx_http_v2_header_t));
        if (entry == NULL) {
            return NGX_ERROR;
        }

    } else {
        entry = h2c->hpack.entries[h2c->hpack.reused++ % h2c->hpack.allocated];
    }

    avail = h2c->hpack.storage + NGX_HTTP_V2_TABLE_SIZE - h2c->hpack.pos;

    entry->name.len = header->name.len;
    entry->name.data = h2c->hpack.pos;

    if (avail >= header->name.len) {
        h2c->hpack.pos = ngx_cpymem(h2c->hpack.pos, header->name.data,
                                    header->name.len);
    } else {
        ngx_memcpy(h2c->hpack.pos, header->name.data, avail);
        h2c->hpack.pos = ngx_cpymem(h2c->hpack.storage,
                                    header->name.data + avail,
                                    header->name.len - avail);
        avail = NGX_HTTP_V2_TABLE_SIZE;
    }

    avail -= header->name.len;

    entry->value.len = header->value.len;
    entry->value.data = h2c->hpack.pos;

    if (avail >= header->value.len) {
        h2c->hpack.pos = ngx_cpymem(h2c->hpack.pos, header->value.data,
                                    header->value.len);
    } else {
        ngx_memcpy(h2c->hpack.pos, header->value.data, avail);
        h2c->hpack.pos = ngx_cpymem(h2c->hpack.storage,
                                    header->value.data + avail,
                                    header->value.len - avail);
    }

    if (h2c->hpack.allocated == h2c->hpack.added - h2c->hpack.deleted) {

        entries = ngx_palloc(h2c->connection->pool,
                             sizeof(ngx_http_v2_header_t *)
                             * (h2c->hpack.allocated + 64));
        if (entries == NULL) {
            return NGX_ERROR;
        }

        index = h2c->hpack.deleted % h2c->hpack.allocated;

        ngx_memcpy(entries, &h2c->hpack.entries[index],
                   (h2c->hpack.allocated - index)
                   * sizeof(ngx_http_v2_header_t *));

        ngx_memcpy(&entries[h2c->hpack.allocated - index], h2c->hpack.entries,
                   index * sizeof(ngx_http_v2_header_t *));

        (void) ngx_pfree(h2c->connection->pool, h2c->hpack.entries);

        h2c->hpack.entries = entries;

        h2c->hpack.added = h2c->hpack.allocated;
        h2c->hpack.deleted = 0;
        h2c->hpack.reused = 0;
        h2c->hpack.allocated += 64;
    }

    h2c->hpack.entries[h2c->hpack.added++ % h2c->hpack.allocated] = entry;

    return NGX_OK;
}


static ngx_int_t
ngx_http_v2_table_account(ngx_http_v2_connection_t *h2c, size_t size)
{
    ngx_http_v2_header_t  *entry;

    size += 32;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 table account: %uz free:%uz",
                   size, h2c->hpack.free);

    if (size <= h2c->hpack.free) {
        h2c->hpack.free -= size;
        return NGX_OK;
    }

    if (size > h2c->hpack.size) {
        h2c->hpack.deleted = h2c->hpack.added;
        h2c->hpack.free = h2c->hpack.size;
        return NGX_DECLINED;
    }

    do {
        entry = h2c->hpack.entries[h2c->hpack.deleted++ % h2c->hpack.allocated];
        h2c->hpack.free += 32 + entry->name.len + entry->value.len;
    } while (size > h2c->hpack.free);

    h2c->hpack.free -= size;

    return NGX_OK;
}


ngx_int_t
ngx_http_v2_table_size(ngx_http_v2_connection_t *h2c, size_t size)
{
    ssize_t                needed;
    ngx_http_v2_header_t  *entry;

    if (size > NGX_HTTP_V2_TABLE_SIZE) {
        ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                      "client sent invalid table size update: %uz", size);

        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 new hpack table size: %uz was:%uz",
                   size, h2c->hpack.size);

    needed = h2c->hpack.size - size;

    while (needed > (ssize_t) h2c->hpack.free) {
        entry = h2c->hpack.entries[h2c->hpack.deleted++ % h2c->hpack.allocated];
        h2c->hpack.free += 32 + entry->name.len + entry->value.len;
    }

    h2c->hpack.size = size;
    h2c->hpack.free -= needed;

    return NGX_OK;
}


#if (NGX_HTTP_V2_HPACK_ENC)

static ngx_int_t
hpack_get_static_index(ngx_http_v2_connection_t *h2c, u_char *val, size_t len);

static ngx_int_t
hpack_get_dynamic_index(ngx_http_v2_connection_t *h2c, uint64_t key_hash,
                        uint8_t *key, size_t key_len);


void
ngx_http_v2_table_resize(ngx_http_v2_connection_t *h2c)
{
    ngx_http_v2_hpack_enc_entry_t  *table;
    uint64_t                        idx;

    table = h2c->hpack_enc.htable;

    while (h2c->hpack_enc.size > h2c->max_hpack_table_size) {
        idx = h2c->hpack_enc.base;
        h2c->hpack_enc.base = table[idx].next;
        h2c->hpack_enc.size -= table[idx].size;
        table[idx].hash_val = 0;
        h2c->hpack_enc.n_elems--;
    }
}


/* checks if a header is in the hpack table - if so returns the table entry,
   otherwise encodes and inserts into the table and returns 0,
   if failed to insert into table, returns -1 */
static ngx_int_t
ngx_http_v2_table_encode_strings(ngx_http_v2_connection_t *h2c,
    size_t key_len, size_t val_len, uint8_t *key, uint8_t *val,
    ngx_int_t *header_idx)
{
    uint64_t  hash_val, key_hash, idx, lru;
    int       i;
    size_t    size = key_len + val_len + 32;
    uint8_t  *storage = h2c->hpack_enc.storage;

    ngx_http_v2_hpack_enc_entry_t   *table;
    ngx_http_v2_hpack_name_entry_t  *name;

    *header_idx = NGX_ERROR;
    /* step 1: compute the hash value of header */
    if (size > HPACK_ENC_MAX_ENTRY || size > h2c->max_hpack_table_size) {
        return NGX_ERROR;
    }

    key_hash = ngx_murmur_hash2_64(key, key_len, 0x01234);
    hash_val = ngx_murmur_hash2_64(val, val_len, key_hash);

    if (hash_val == 0) {
        return NGX_ERROR;
    }

    /* step 2: check if full header in the table */
    idx = hash_val;
    i = -1;
    while (idx) {
         /* at most 8 locations are checked, but most will be done in 1 or 2 */
        table = &h2c->hpack_enc.htable[idx % HPACK_ENC_HTABLE_SZ];
        if (table->hash_val == hash_val
            && table->klen == key_len
            && table->vlen == val_len
            && ngx_memcmp(key, storage + table->pos, key_len) == 0
            && ngx_memcmp(val, storage + table->pos + key_len, val_len) == 0)
        {
            return (h2c->hpack_enc.top - table->index) + 61;
        }

        if (table->hash_val == 0 && i == -1) {
            i = idx % HPACK_ENC_HTABLE_SZ;
            break;
        }

        idx >>= 8;
    }

    /* step 3: check if key is in one of the tables */
    *header_idx = hpack_get_static_index(h2c, key, key_len);

    if (i == -1) {
        return NGX_ERROR;
    }

    if (*header_idx == NGX_ERROR) {
        *header_idx = hpack_get_dynamic_index(h2c, key_hash, key, key_len);
    }

    /* step 4: store the new entry */
    table =  h2c->hpack_enc.htable;

    if (h2c->hpack_enc.top == 0xffffffff) {
        /* just to be on the safe side, avoid overflow */
        ngx_memset(&h2c->hpack_enc, 0, sizeof(ngx_http_v2_hpack_enc_t));
    }

    while ((h2c->hpack_enc.size + size > h2c->max_hpack_table_size)
           || h2c->hpack_enc.n_elems == HPACK_ENC_HTABLE_ENTRIES) {
        /* make space for the new entry first */
        idx = h2c->hpack_enc.base;
        h2c->hpack_enc.base = table[idx].next;
        h2c->hpack_enc.size -= table[idx].size;
        table[idx].hash_val = 0;
        h2c->hpack_enc.n_elems--;
    }

    table[i] = (ngx_http_v2_hpack_enc_entry_t){.hash_val = hash_val,
                                               .index = h2c->hpack_enc.top,
                                               .pos = h2c->hpack_enc.pos,
                                               .klen = key_len,
                                               .vlen = val_len,
                                               .size = size,
                                               .next = 0};

    table[h2c->hpack_enc.last].next = i;
    if (h2c->hpack_enc.n_elems == 0) {
        h2c->hpack_enc.base = i;
    }

    h2c->hpack_enc.last = i;
    h2c->hpack_enc.top++;
    h2c->hpack_enc.size += size;
    h2c->hpack_enc.n_elems++;

    /* update header name lookup */
    if (*header_idx == NGX_ERROR ) {
        lru = h2c->hpack_enc.top;

        for (i=0; i<HPACK_ENC_DYNAMIC_KEY_TBL_SZ; i++) {

            name = &h2c->hpack_enc.heads[i];

            if ( name->hash_val == 0 || (name->hash_val == key_hash
                && ngx_memcmp(storage + name->pos, key, key_len) == 0) )
            {
                name->hash_val = key_hash;
                name->pos = h2c->hpack_enc.pos;
                name->index = h2c->hpack_enc.top - 1;
                break;
            }

            if (lru > name->index) {
                lru = name->index;
                idx = i;
            }
        }

        if (i == HPACK_ENC_DYNAMIC_KEY_TBL_SZ) {
            name = &h2c->hpack_enc.heads[idx];
            name->hash_val = hash_val;
            name->pos = h2c->hpack_enc.pos;
            name->index = h2c->hpack_enc.top - 1;
        }
    }

    ngx_memcpy(storage + h2c->hpack_enc.pos, key, key_len);
    ngx_memcpy(storage + h2c->hpack_enc.pos + key_len, val, val_len);

    h2c->hpack_enc.pos += size;
    if (h2c->hpack_enc.pos > NGX_HTTP_V2_MAX_HPACK_TABLE_SIZE) {
        h2c->hpack_enc.pos = 0;
    }

    return NGX_OK;
}


u_char *
ngx_http_v2_write_header(ngx_http_v2_connection_t *h2c, u_char *pos,
                         u_char *key, size_t key_len,
                         u_char *value, size_t value_len,
                         u_char *tmp)
{
    ngx_int_t idx, header_idx;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 output header: %*s: %*s", key_len, key, value_len,
                   value);

    /* attempt to find the value in the dynamic table */
    idx = ngx_http_v2_table_encode_strings(h2c, key_len, value_len, key, value,
                                           &header_idx);

    if (idx > 0) {
        /* positive index indicates success */
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                       "http2 hpack encode: Indexed Header Field: %ud", idx);

        *pos = 128;
        pos = ngx_http_v2_write_int(pos, ngx_http_v2_prefix(7), idx);

    } else {

        if (header_idx == NGX_ERROR) { /* if key is not present */

            if (idx == NGX_ERROR) {    /* if header was not added */
                *pos++ = 0;

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                              "http2 hpack encode: Literal Header Field without"
                              " Indexing — New Name");
            } else {                   /* if header was added */
                *pos++ = 64;

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                              "http2 hpack encode: Literal Header Field with "
                              "Incremental Indexing — New Name");
            }

            pos = ngx_http_v2_write_name(pos, key, key_len, tmp);

        } else {                       /* if key is present */

            if (idx == NGX_ERROR) {
                *pos = 0;
                pos = ngx_http_v2_write_int(pos, ngx_http_v2_prefix(4), header_idx);

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                              "http2 hpack encode: Literal Header Field without"
                              " Indexing — Indexed Name: %ud", header_idx);
            } else {
                *pos = 64;
                pos = ngx_http_v2_write_int(pos, ngx_http_v2_prefix(6), header_idx);

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                              "http2 hpack encode: Literal Header Field with "
                              "Incremental Indexing — Indexed Name: %ud", header_idx);
            }
        }

        pos = ngx_http_v2_write_value(pos, value, value_len, tmp);
    }

    return pos;
}


static ngx_int_t
hpack_get_dynamic_index(ngx_http_v2_connection_t *h2c, uint64_t key_hash,
                        uint8_t *key, size_t key_len)
{
    ngx_http_v2_hpack_name_entry_t  *name;
    int                              i;

    for (i=0; i<HPACK_ENC_DYNAMIC_KEY_TBL_SZ; i++) {
        name = &h2c->hpack_enc.heads[i];

        if (name->hash_val == key_hash
            && ngx_memcmp(h2c->hpack_enc.storage + name->pos, key, key_len) == 0)
        {
            if (name->index >= h2c->hpack_enc.top - h2c->hpack_enc.n_elems) {
                return (h2c->hpack_enc.top - name->index) + 61;
            }
            break;
        }
    }

    return NGX_ERROR;
}


/* decide if a given header is present in the static dictionary, this could be
   done in several ways, but it seems the fastest one is "exhaustive" search */
static ngx_int_t
hpack_get_static_index(ngx_http_v2_connection_t *h2c, u_char *val, size_t len)
{
    /* the static dictionary of response only headers,
       although response headers can be put by origin,
       that would be rare */
    static const struct {
        u_char         len;
        const u_char   val[28];
        u_char         idx;
    } server_headers[] = {
        { 3, "age",                         21},//0
        { 3, "via",                         60},
        { 4, "date",                        33},//2
        { 4, "etag",                        34},
        { 4, "link",                        45},
        { 4, "vary",                        59},
        { 5, "allow",                       22},//6
        { 6, "server",                      54},//7
        { 7, "expires",                     36},//8
        { 7, "refresh",                     52},
        { 8, "location",                    46},//10
        {10, "set-cookie",                  55},//11
        {11, "retry-after",                 53},//12
        {12, "content-type",                31},//13
        {13, "content-range",               30},//14
        {13, "accept-ranges",               18},
        {13, "cache-control",               24},
        {13, "last-modified",               44},
        {14, "content-length",              28},//18
        {16, "content-encoding",            26},//19
        {16, "content-language",            27},
        {16, "content-location",            29},
        {16, "www-authenticate",            61},
        {17, "transfer-encoding",           57},//23
        {18, "proxy-authenticate",          48},//24
        {19, "content-disposition",         25},//25
        {25, "strict-transport-security",   56},//26
        {27, "access-control-allow-origin", 20},//27
        {99, "",                            99},
    }, *header;

    /* for a given length, where to start the search
       since minimal length is 3, the table has a -3
       offset */
    static const int8_t start_at[] = {
        [3-3]  = 0,
        [4-3]  = 2,
        [5-3]  = 6,
        [6-3]  = 7,
        [7-3]  = 8,
        [8-3]  = 10,
        [9-3]  = -1,
        [10-3] = 11,
        [11-3] = 12,
        [12-3] = 13,
        [13-3] = 14,
        [14-3] = 18,
        [15-3] = -1,
        [16-3] = 19,
        [17-3] = 23,
        [18-3] = 24,
        [19-3] = 25,
        [20-3] = -1,
        [21-3] = -1,
        [22-3] = -1,
        [23-3] = -1,
        [24-3] = -1,
        [25-3] = 26,
        [26-3] = -1,
        [27-3] = 27,
    };

    uint64_t pref;
    size_t   save_len = len, i;
    int8_t   start;

    /* early exit for out of bounds lengths */
    if (len < 3 || len > 27) {
        return NGX_ERROR;
    }

    start = start_at[len - 3];
    if (start == -1) {
        /* exit for non existent lengths */
        return NGX_ERROR;
    }

    header = &server_headers[start_at[len - 3]];

    /* load first 8 bytes of key, for fast comparison */
    if (len < 8) {
        pref = 0;
        if (len >= 4) {
            pref = *(uint32_t *)(val + len - 4) | 0x20202020;
            len -= 4;
        }
        while (len > 0) { /* 3 iterations at most */
            pref = (pref << 8) ^ (val[len - 1] | 0x20);
            len--;
        }
    } else {
        pref = *(uint64_t *)val | 0x2020202020202020;
        len -= 8;
    }

    /* iterate over headers with the right length */
    while (header->len == save_len) {
        /* quickly compare the first 8 bytes, most tests will end here */
        if (pref != *(uint64_t *) header->val) {
            header++;
            continue;
        }

        if (len == 0) {
            /* len == 0, indicates prefix held the entire key */
            return header->idx;
        }
        /* for longer keys compare the rest */
        i = 1 + (save_len + 7) % 8; /* align so we can compare in quadwords */

        while (i + 8 <= save_len) { /* 3 iterations at most */
            if ( *(uint64_t *)&header->val[i]
                 != (*(uint64_t *) &val[i]| 0x2020202020202020) )
            {
                header++;
                i = 0;
                break;
            }
            i += 8;
        }

        if (i == 0) {
            continue;
        }

        /* found the corresponding entry in the static dictionary */
        return header->idx;
    }

    return NGX_ERROR;
}

#else

u_char *
ngx_http_v2_write_header(ngx_http_v2_connection_t *h2c, u_char *pos,
                         u_char *key, size_t key_len,
                         u_char *value, size_t value_len,
                         u_char *tmp)
{
    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 output header: %*s: %*s", key_len, key, value_len,
                   value);

    *pos++ = 64;
    pos = ngx_http_v2_write_name(pos, key, key_len, tmp);
    pos = ngx_http_v2_write_value(pos, value, value_len, tmp);

    return pos;
}

#endif
