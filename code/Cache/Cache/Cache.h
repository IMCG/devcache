#ifndef CACHE_H
#define CACHE_H

/* data structures */
typedef enum {
	CACHE_ERROR_success=0,
	CACHE_ERROR_invalidctx,
	CACHE_ERROR_unknowntype,
	CACHE_ERROR_memoryerror,
	CACHE_ERROR_invalidictx,
	CACHE_ERROR_internalerror,
	CACHE_ERROR_LAST
} CACHE_ERROR;
extern char* CACHE_ERRORSTR[CACHE_ERROR_LAST+1];
/* =
{
"CACHE_ERROR_success",
"CACHE_ERROR_invalidctx",
"CACHE_ERROR_unknowntype",
"CACHE_ERROR_memoryerror",
"CACHE_ERROR_invalidictx",
"CACHE_ERROR_internalerror",

"CACHE_ERROR_unknown_error"
};
*/

#define CACHE_ERROR2STR(err) ((err>=0&&err<CACHE_ERROR_LAST)?CACHE_ERRORSTR[err]:CACHE_ERRORSTR[CACHE_ERROR_LAST])

typedef enum {
	CACHE_TYPE_default=0,
	CACHE_TYPE_WN_LRU,
	CACHE_TYPE_WN_MRU,
	CACHE_TYPE_WT_LRU,
	CACHE_TYPE_WT_MRU,
	CACHE_TYPE_LAST
} CACHE_TYPE;


#ifndef BYTE
typedef unsigned char BYTE;
#endif
#ifndef BOOL
#ifdef bool
typedef bool BOOL;
//#define TRUE true
//#define FALSE false
#else
typedef int BOOL;
#define FALSE 0
#define TRUE 1
#endif
#endif

/* function pointers for reading and writing to cached device */
//*
typedef unsigned long long ADDRESS;
/*/
typedef union {
	unsigned long long lu;
	void* p;
} ADDRESS;
//*/
typedef struct CACHE_DEVOPS_st {
	BOOL (*read)(void* arg, ADDRESS address, BYTE* data, size_t sz);
	BOOL (*write)(void* arg, ADDRESS address, BYTE* data, size_t sz);
	BOOL (*alloc)(void* arg, ADDRESS* address, size_t sz);
	BOOL (*free)(void* arg, ADDRESS address, size_t sz);
	void* opaque_data;
	unsigned char log2_blocksize;
	unsigned long long num_blocks;
	BOOL supportsAsync;
	int (*asyncwrite)(void* arg, ADDRESS address, BYTE* data, size_t sz, void* context, void (*callback)(void*,int));
} CACHE_DEVOPS, *PCACHE_DEVOPS;

/* function pointers for memory usage by the cache code */
typedef struct CACHE_MEMOPS {
	void* (*malloc)(size_t);
	void (*free)(void*);
	void* (*realloc)(void *, size_t);	
} CACHE_MEMOPS, *PCACHE_MEMOPS;

typedef struct CACHE_CTX_st {
	CACHE_TYPE type;
	CACHE_ERROR error;
	CACHE_MEMOPS mem_ops;
	CACHE_DEVOPS dev_ops;
	CACHE_DEVOPS cache_ops;
	BOOL initialized;
	void* internal_data;
} CACHE_CTX, *PCACHE_CTX;


BOOL CACHE_init(PCACHE_CTX ctx,CACHE_TYPE type);
BOOL CACHE_destroy(PCACHE_CTX ctx);
BOOL CACHE_get(PCACHE_CTX ctx, ADDRESS addr, BYTE* data, size_t sz);
BOOL CACHE_put(PCACHE_CTX ctx, ADDRESS addr, BYTE* data, size_t sz);
#endif

