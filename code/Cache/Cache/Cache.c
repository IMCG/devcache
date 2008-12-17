// Cache.cpp : Defines the entry point for the console application.
//

#ifdef __KERNEL__
#define GCC
#endif

#ifndef __KERNEL__
#ifndef GCC
#include "stdafx.h"
#endif
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"list.h"
#else
#include<linux/kernel.h>
#define printf(args...) printk(KERN_WARNING args)
#include<linux/list.h>
#endif

#ifndef DEBUGLEVEL
#define DEBUGLEVEL 1
#endif

#ifdef _DEBUG
#define DEBUG
#endif
#ifdef DEBUG
#define DBGL(l,x) if(DEBUGLEVEL&l) {x}
#define DBG(x...) DBGL(128,x)
#define dprintf printf
#else
#define DBG(x)
#define DBGL(l,x)
#endif

#include"hash_table.h"

#include "Cache.h"


char* CACHE_ERRORSTR[CACHE_ERROR_LAST+1] =
{
"CACHE_ERROR_success",
"CACHE_ERROR_invalidctx",
"CACHE_ERROR_unknowntype",
"CACHE_ERROR_memoryerror",
"CACHE_ERROR_invalidictx",
"CACHE_ERROR_internalerror",

"CACHE_ERROR_unknown_error"
};

/* Cache Implementation */

/* notes */
/*	will pull in list.h from the linux kernel - userspace version available for testing and other tasks
	will use hashtable written by Kalesh http://isis.poly.edu/kulesh/stuff/src/ although altered to use linux spinlocks instead of pthread_mutex for kernel space

	instead of simple single cache, the policy (whether LRU, MRU, etc) should be split across processes
		eg.  the least recently used should be a local policy, so each node will be simultaniously in a
		local access ordered list, global access ordered list, and global hash table.  The local access
		ordered lists will be pointed to by another hashtable (called mux-hash?).  Then the new issue is
		upon a new idem in mux-hash (new process) how to make room for it...i guess apply the global 
		LRU/MRU policy then.  Now the real problem, how do i code for two processing accessing the same block?
		Basically how syntactically can it be in both local linked lists???

	make the ADDRESS actually a union with a void* p, and unsigned long long b (blockid)?
*/
/* Exposed API:
	return true/false for success, with additional errors inside the context
	first parameter always PCACHE_CTX
	This set of functions always checks validity of PCACHE_CTX, (internal functions never do)
	Parameters should be structures when possible to support plugging this into other outer implementations?

	
	
	*/
/* Internal API:
	set CACHE_ERROR and return true/false
	not validate PCACHE_CTX;
	first parameter always PCACHE_ICTX (internal ctx)
	*/

/* internal api */
#define CACHE_malloc(size) ctx->mem_ops.malloc(size)
#define CACHE_free(p) ctx->mem_ops.free(p)
#define CACHE_realloc(p,size) ctx->mem_ops.realloc(p,size)

#ifdef _DEBUG //implies WIN32
#define VALIDCODE(p) (p!=NULL && ((void*)p!=(void*)0xCDCDCDCDCDCDCDCD)) //may be better set depending on OS
#define VALIDDATA(p) (p!=NULL && ((void*)p!=(void*)0xCDCDCDCDCDCDCDCD)) //may be better test depending on OS
#else
#define VALIDCODE(p) (p!=NULL) //may be better set depending on OS
#define VALIDDATA(p) (p!=NULL) //may be better test depending on OS
#endif

#define _PCACHE_ICTX(ctx) ((PCACHE_ICTX)((ctx)->internal_data))
#define _PCACHE_CTX(ictx) ((ictx)->ctx)


typedef struct IADDRESS_st {
	ADDRESS addr;
	unsigned long long offset;
	size_t sz;
	ADDRESS eaddr;
} IADDRESS; //a cache line address?

#ifdef WIN32
typedef struct CACHE_ICTX_st *PCACHE_ICTX;
#else
struct CACHE_ICTX_st;
#endif
typedef BOOL (*ictx_get)(struct CACHE_ICTX_st* ictx, ADDRESS addr, BYTE* data, size_t sz);//get function
typedef BOOL (*ictx_put)(struct CACHE_ICTX_st* ictx, ADDRESS addr, BYTE* data, size_t sz);//put function

typedef struct CACHE_ICTX_st {
	PCACHE_CTX ctx;
	ictx_get get;
	ictx_put put;
	void* data;
} CACHE_ICTX, *PCACHE_ICTX;

CACHE_ERROR CACHEi_validatectx(PCACHE_CTX ctx)
{
	if(
		!VALIDCODE(ctx->dev_ops.read) ||
		!VALIDCODE(ctx->dev_ops.write) ||
		ctx->dev_ops.num_blocks==0 ||
		ctx->dev_ops.log2_blocksize==0 ||
		!VALIDCODE(ctx->cache_ops.read) ||
		!VALIDCODE(ctx->cache_ops.write) ||
		!VALIDCODE(ctx->cache_ops.alloc) ||
		!VALIDCODE(ctx->cache_ops.free) ||
		ctx->cache_ops.num_blocks==0 ||
		ctx->cache_ops.log2_blocksize==0 ||
		!VALIDCODE(ctx->mem_ops.malloc) ||
		!VALIDCODE(ctx->mem_ops.free) ||
		!VALIDCODE(ctx->mem_ops.realloc) ||
		(ctx->initialized && !VALIDDATA(ctx->internal_data))
		)
		return CACHE_ERROR_invalidctx;
	return CACHE_ERROR_success;

}

CACHE_ERROR CACHEi_validateictx(PCACHE_CTX ctx)
{
	PCACHE_ICTX ictx = _PCACHE_ICTX(ctx);
	if(
		!ctx->initialized ||
		!VALIDCODE(ictx->get) ||
		!VALIDCODE(ictx->put)
		)
		return CACHE_ERROR_invalidictx;
	{
		PCACHE_CTX octx = _PCACHE_CTX(ictx);
		if(octx!=ctx) 	return CACHE_ERROR_invalidictx;
	}

	return CACHE_ERROR_success;

}

CACHE_ERROR CACHEi_initdefault(PCACHE_CTX ctx)
{
	if(!(ctx->internal_data = CACHE_malloc(sizeof(CACHE_ICTX)))) return CACHE_ERROR_memoryerror;
	_PCACHE_ICTX(ctx)->ctx=ctx;
	ctx->initialized=TRUE;
	return CACHE_ERROR_success;
}

CACHE_ERROR CACHEi_destroydefault(PCACHE_CTX ctx)
{
	if(ctx->initialized) CACHE_free(ctx->internal_data);
	ctx->initialized=FALSE;
	return CACHE_ERROR_success;
}

//////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////
//// GENERIC CACHE IMPLEMENTATION
/**
 * hash_entry - get the user data for this entry
 * @ptr:	the &struct hash_entry pointer
 * @type:	the type of the user data (e.g. struct my_data) embedded in this entry
 * @member:	the name of the hash_entry within the struct (e.g. entry)
 */
#define cache_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(unsigned long long)(&((type *)0)->member)))

typedef struct cache_node_st {
	struct hash_entry incache_hashentry;	//node is part of hash table
	struct list_head access_list;	//node is part of access time ordered list (for eviction policy)
	generic_mutex_t lock;
} cache_node, *pcache_node;

typedef struct cached_data_st {
	ADDRESS addr;
	BYTE* p;
	generic_mutex_t lock;
	cache_node cnode;
} cached_data;

typedef enum cache_imp_inserttype_e {
	cache_imp_inserttype_default=0, //default
	cache_imp_inserttype_back,	//LRU
	cache_imp_inserttype_front,		//MRU
	cache_imp_inserttype_random,	//Random
} cache_imp_inserttype;

typedef enum cache_imp_cachetype_e {
	cache_imp_cachetype_default=0, //default
	cache_imp_cachetype_LRU,
	cache_imp_cachetype_MRU,
	cache_imp_cachetype_random,
} cache_imp_cachetype;

typedef struct cache_imp_st
{
	cache_imp_inserttype insertwhere;
	struct hash_table hash;
	struct list_head list;
	unsigned long long max_size;
	unsigned long long size;
	generic_mutex_t lock;
} cache_imp, *pcache_imp;

#define cache_malloc hash_table_malloc
#define cache_free hash_table_free

BOOL cache_imp_init(cache_imp* cache, unsigned long long sz, cache_imp_cachetype cache_type)
{
	DBGL(2,{ dprintf("cache_imp_init: sz:0x%08llx type:%d\n",sz,cache_type); })

	/* initialize the hash table with buckets */
	hash_table_init(&(cache->hash), sz>(1<<10)?(1<<10):(unsigned int)sz, NULL);

	/* initialize the access time ordered list */
	INIT_LIST_HEAD(&(cache->list));

	cache->max_size = sz;
	cache->size = 0;

	cache->insertwhere = (cache_imp_inserttype)cache_type;

	generic_mutex_init(&cache->lock,NULL);

	return TRUE;
}

BOOL cache_imp_fini(cache_imp* cache)
{
	/* cleanup hash table */
	hash_table_finit(&cache->hash);
    /* cleanup each remaining item in the cache */
    {struct list_head *pos,*n;
	list_for_each_safe(pos, n, &cache->list)
	{
			cache_node* node = list_entry(pos,cache_node,access_list);
			if(node) {
		        cache_free(cache_entry(node,cached_data,cnode));
            }
	}}
	/* cleanup linked list my making it empty (although really just for safety)  */
    INIT_LIST_HEAD(&cache->list);
	return TRUE;
}

BOOL cache_imp_list_insert(cache_imp* cache, cache_node* node, cache_imp_inserttype insert_where)
{
	DBG({dprintf("cache_imp_list_insert: node:%p where:%d\n",node,insert_where);})

	switch(insert_where) {
	case cache_imp_inserttype_default: //default to LRU
	case cache_imp_inserttype_back:	//LRU
		list_add_tail(&node->access_list, &cache->list);
		break;
	case cache_imp_inserttype_front:		//MRU
		list_add(&node->access_list, &cache->list);
		break;
	case cache_imp_inserttype_random:
		//not implemented
		//break;
	default:
		return FALSE;
	};
	return TRUE;
}

BOOL cache_imp_insert(cache_imp* cache, ADDRESS* addr, cache_node* node, cache_imp_inserttype insert_where)
{
	DBG({dprintf("cache_imp_insert: &addr:%p node:%p where:%d\n",addr,node,insert_where);})
	DBG(if(addr){dprintf("cache_imp_insert (ADDR): addr:%llx node:%p where:%d\n",*addr,node,insert_where);})

	/* insert into access list at front or back */
	if(!cache_imp_list_insert(cache,node,insert_where)) return FALSE;

	/* insert into hash table */
	hash_table_insert_safe(&cache->hash, &node->incache_hashentry, (unsigned char*)addr, sizeof(ADDRESS));

	return TRUE;
}


BOOL cache_imp_evict(cache_imp* cache);
cache_node* cache_imp_try(cache_imp* cache, ADDRESS* addr);

BOOL cache_retrieve_evictee(cache_imp* cache, cache_node** evictee)
{
	BOOL rtn = FALSE;
	DBG( { dprintf("cache_retrieve_evictee %c\n",' '); } )

	if(!cache || !evictee) return FALSE;
	generic_mutex_lock(&cache->lock);
	{
		struct list_head *pos,*n;
		list_for_each_safe(pos, n, &cache->list)
		{
			cache_node* node = list_entry(pos,cache_node,access_list);
			if(!node) goto cache_imp_retrieve_evictee_cleanup;
			*evictee = node;
			generic_mutex_lock(&node->lock);
			rtn=TRUE;
			break;
		}
	}

cache_imp_retrieve_evictee_cleanup:
	generic_mutex_unlock(&cache->lock);
	return FALSE;
}

BOOL cache_release_evictee(cache_imp* cache, cache_node* evictee)
{
	if(!cache || !evictee) return FALSE;	
	generic_mutex_unlock(&evictee->lock);
	return TRUE;
}

BOOL cache_imp_remove(cache_imp* cache, cache_node* node);
BOOL cache_reinsert_node(cache_imp* cache, ADDRESS* addr, cache_node* node)
{
	BOOL rtn = FALSE;
	DBG({dprintf("cache_reinsert_node: &addr: %p node:%p\n",addr,node);})

	if(!cache || !node) return FALSE;

	generic_mutex_lock(&cache->lock);

	/* new key */
	if(addr!=NULL)
	{
		DBG({dprintf("cache_reinsert_node: NEW KEY addr: %llx node:%p\n",*addr,node);})
		if(!cache_imp_remove(cache,node))
		{
			rtn=FALSE;
			goto cache_imp_reinsert_dataptr_cleanup;
		}
		if(!cache_imp_insert(cache,addr,node,cache->insertwhere))
		{
			rtn=FALSE;
			goto cache_imp_reinsert_dataptr_cleanup;
		}
		rtn=TRUE;
	}
	else /* old key */
	{
		list_del(&node->access_list);
		if(!cache_imp_list_insert(cache,node,cache->insertwhere))
		{
			rtn=FALSE;
			goto cache_imp_reinsert_dataptr_cleanup;
		}
		rtn=TRUE;
	}
	generic_mutex_unlock(&node->lock);

cache_imp_reinsert_dataptr_cleanup:
	generic_mutex_unlock(&cache->lock);
	return rtn;
}

BOOL cache_touch_node(cache_imp* cache, cache_node* node)
{
	BOOL rtn = TRUE;
	DBG({dprintf("cache_touch_node: %p\n",node);})

	if(!cache || !node) return FALSE;

	generic_mutex_lock(&cache->lock);

	list_del(&node->access_list);
	if(!cache_imp_list_insert(cache,node,cache->insertwhere))
	{
		rtn=FALSE;
	}

	generic_mutex_unlock(&cache->lock);
	return rtn;
}

BOOL cache_insert_node(cache_imp* cache, ADDRESS* addr, cache_node* node)
{
	BOOL rtn = FALSE;
	DBG({dprintf("cache_insert_node: &addr: %p node:%p\n",addr,node);})

	if(!cache || !addr || !node) return FALSE;

	DBG({dprintf("cache_insert_node (ADDR): addr: %llx node:%p\n",*addr,node);})

	generic_mutex_lock(&cache->lock);

	if((cache->size>=cache->max_size) && !cache_imp_evict(cache)) goto cache_imp_insert_data_cleanup;
	
	{
		generic_mutex_init(&node->lock,NULL);
		if(!cache_imp_insert(cache,addr,node,cache->insertwhere))
		{
			goto cache_imp_insert_data_cleanup;
		}
#ifdef OLD_CODE
		cache_node* node = cache_imp_try(cache, addr);
		if(!node) {
			node = &data->cnode;
			generic_mutex_init(&node->lock,NULL);
			if(!cache_imp_insert(cache,addr,node,cache->insertwhere))
			{
				goto cache_imp_insert_data_cleanup;
			}
		}else{
			if(!cache_imp_reinsert(cache,node))
			{
				goto cache_imp_insert_data_cleanup;
			}
		}
#endif
	}
	cache->size+=1;
	rtn = TRUE;

cache_imp_insert_data_cleanup:
	generic_mutex_unlock(&cache->lock);
	return rtn;
}

BOOL cache_retrieve_node(cache_imp* cache, ADDRESS* addr, cache_node** node)
{
	BOOL rtn = FALSE;
	DBG({dprintf("cache_retrieve_node: addr:%p\n",addr);})

	if(!cache || !addr || !node) return FALSE;

	DBG({dprintf("cache_retrieve_node (ADDR): addr:0x%08llx\n",*addr);})

	generic_mutex_lock(&cache->lock);

	{
		*node = cache_imp_try(cache, addr);
		if(!*node) goto cache_imp_retrieve_dataptr_cleanup;
		generic_mutex_lock(&(*node)->lock);
		rtn=TRUE;
	}

cache_imp_retrieve_dataptr_cleanup:
	generic_mutex_unlock(&cache->lock);
	return rtn;
}

BOOL cache_release_node(cache_imp* cache, cache_node* node)
{
	DBG({dprintf("cache_release_node: node:%p\n",node);})

	if(!cache || !node) return FALSE;

	generic_mutex_unlock(&node->lock);
	
	return TRUE;
}


cache_node* cache_imp_try(cache_imp* cache, ADDRESS* addr)
{
	cache_node *tmp;
	struct hash_entry *hentry;

	DBG({dprintf("cache_imp_try: addr:%p\n",addr);})
	DBG(if(addr){dprintf("cache_imp_try (ADDR): addr:0x%08llx\n",*addr);})


	if ((hentry =
	     hash_table_lookup_key_safe(&cache->hash, (const unsigned char*)addr,
				   sizeof(ADDRESS))) == NULL) {
		tmp = NULL;
	} else {
		/* just like the list_item() */
		tmp = hash_entry(hentry, cache_node, incache_hashentry);
	}
	return tmp;
}

BOOL cache_imp_remove(cache_imp* cache, cache_node* node)
{
	/* remove from hash */
	struct hash_entry *hentry = hash_table_del_hash_entry_safe(&cache->hash,&node->incache_hashentry);
	if(!hentry) return FALSE;
	hash_entry_finit(hentry);
	/* remove from list */
	list_del(&node->access_list);
	return TRUE;
}

BOOL cache_imp_evict(cache_imp* cache)
{
	struct list_head *pos,*n;
evict_restart:
	DBG({dprintf("cache_imp_evict\n");})

	list_for_each_safe(pos, n, &cache->list)
	{
		cache_node* node = list_entry(pos,cache_node,access_list);
		if(!node) return FALSE;
		generic_mutex_lock(&node->lock); // XXX lock issue?
		if(&node->access_list!=cache->list.next) goto evict_restart; //evictee has been moved
		if(!cache_imp_remove(cache,node)) return FALSE;
		cache->size-=1;
		cache_free(cache_entry(node,cached_data,cnode));
		break;//only evict front entry
	}
	return TRUE; //if empty
}


//////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////


/*** FIX implment: async callback will lock the entry, free/null buff, unlock entry ***/
typedef struct WN_cache_asyncwrite_callback_data_st {
	PCACHE_ICTX ictx;
	cached_data* mdataptr;
	generic_atomic_t sem_cnt;
} WN_cache_asyncwrite_callback_data;
void WN_cache_asyncwrite_callback(void* arg, int ret)
{
	WN_cache_asyncwrite_callback_data* cbdata = (WN_cache_asyncwrite_callback_data*)arg;
	if(generic_atomic_dec_and_test(&cbdata->sem_cnt)==0)
	{
		void* p;
		generic_mutex_lock(&cbdata->mdataptr->lock);
		p = cbdata->mdataptr->p;
		/* if not marked dirty, free */
		if(p!=(void*)-1)
		{
			cbdata->ictx->ctx->mem_ops.free(p);
			cbdata->mdataptr->p=NULL;
		}
		generic_mutex_unlock(&cbdata->mdataptr->lock);
		cbdata->ictx->ctx->mem_ops.free(cbdata);
	}
}

BOOL CACHEi_MakeCacheNode(PCACHE_ICTX ictx, cached_data** cdata, BOOL* gotEvictee)
{
	cache_imp* cache = (cache_imp*) ictx->data;
	cache_node* cnode;
	cached_data* mdataptr=NULL;

	DBG({dprintf("CACHEi_MakeCacheNode\n");})


	/* if cant get evictee (aka not full) make new entry  */
	if(!cache_retrieve_evictee(cache,&cnode))
	{
		DBG({dprintf("\t evictee NOT found\n");})

		if(gotEvictee) *gotEvictee=FALSE;

		/* create new entry for cache */
		mdataptr = cache_malloc(sizeof(cached_data));
		if(!mdataptr) {
			return FALSE;
		}
		generic_mutex_init(&mdataptr->lock,NULL);
	}
	else /* got evictee, alter and reinsert */
	{
		DBG({dprintf("\t evictee FOUND\n");})

		if(gotEvictee) *gotEvictee=TRUE;

		mdataptr = cache_entry(cnode, cached_data, cnode);
	}

	if(cdata) *cdata = mdataptr;
	return TRUE;
}


#define DEV_PRIMARY 0
#define DEV_CACHE 1
#define DEV_READ 0
#define DEV_WRITE 1
#define DEV_ALLOC 2
#define DEV_AWRITE 3
#define DEV_AWRITE_WAITCOMPLETE 4
#define DEV_AWRITE_NOTSUPPORTED -3

#define DevOp(ictx, device, addr, bytelen, data, op) \
    DevOpEx(ictx, device, addr, bytelen, data, op, NULL)

inline int DevOpEx(PCACHE_ICTX ictx, int device, ADDRESS* addr, size_t bytelen, void* data, int op, void*** completions)
{
    unsigned int i,num_ops;
    unsigned int blocksize;

    DBGL(4,{dprintf("DevOp: %p %s %p=%08llx %d %p %d\n",ictx,device==DEV_PRIMARY?"PRIMARY":"CACHE",addr,*addr,bytelen,data,op);})

    CACHE_DEVOPS* ops;
    if(device==DEV_PRIMARY)
	 ops = &ictx->ctx->dev_ops;
    if(device==DEV_CACHE)
	 ops = &ictx->ctx->cache_ops;

	num_ops = bytelen>>ops->log2_blocksize; // assumes bytelen is multiple of blocksize
	blocksize = (1<<ops->log2_blocksize);

	if(ictx->ctx->use_object_interface)
    {
        /* force single operation */
        num_ops=1;
        /* note that pointer arithmetic below should 
         * always yield original object */
    }

    if(op==DEV_AWRITE || op==DEV_AWRITE_WAITCOMPLETE)
    {
        if(!ops->supportsAsync)
        {
            if(completions) *completions=NULL;
            return DEV_AWRITE_NOTSUPPORTED;
        }
        if(op==DEV_AWRITE_WAITCOMPLETE && !completions)
            return -1;

        if(completions) {
            *completions = (void**)cache_malloc(sizeof(void*)*num_ops);
        }
    }

    if(num_ops < 1 && op!=DEV_ALLOC) //return -1; //error must read/write/alloc full blocks
    {
        /* will need to malloc space and memcpy (this is slow!) */
        /* for read and write */
        {
            void* block = cache_malloc(blocksize);
            if(!block) return -2;
        	if(0!=ops->read(ops->opaque_data,*addr,block,blocksize)) {
                cache_free(block);
                return -1;
            }
            if(op==DEV_READ)
            {
                memcpy(data,block,bytelen);
            }
            else
            {
                memcpy(block,data,bytelen);
        	    if(0!=ops->write(ops->opaque_data,*addr,block,blocksize)) {
                    cache_free(block);
                    return -1;
                }
            }
            cache_free(block);
            return 0;
        }
    }

    for(i=0;i<num_ops;++i) {
        if(op==DEV_READ)
        	if(0!=ops->read(ops->opaque_data,*addr+i*blocksize,data+i*blocksize,blocksize)) return -1;
        if(op==DEV_WRITE)
        	if(0!=ops->write(ops->opaque_data,*addr+i*blocksize,data+i*blocksize,blocksize)) return -1;
        if(op==DEV_AWRITE)
        	if(0!=ops->asyncwrite(ops->opaque_data,*addr+i*blocksize,data+i*blocksize,blocksize, completions?(&((*completions)[i])):NULL )) return -1;
        if(op==DEV_AWRITE_WAITCOMPLETE)
        	if(0!=ops->asyncwritewaitcomplete(ops->opaque_data,*addr+i*blocksize,data+i*blocksize,blocksize, completions?((*completions)[i]):NULL )) return -1;
    }
    /* special case with ALLOC.
     *  expected to allocate contiguous multiblock segments */
        if(op==DEV_ALLOC) {
            size_t allocsz = (bytelen+(blocksize-1))/blocksize; //round up
        	if(0!=ops->alloc(ops->opaque_data,addr,allocsz)) return -1;

        }

    if(op==DEV_AWRITE_WAITCOMPLETE) {
        cache_free(*completions);
        *completions=NULL;
    }

    return 0;
}

#define WNWT_getput_diskblock( ictx,  addr,  data, isPut, isThru) \
    WNWT_getput_diskblock_obj(ictx,addr,data,isPut,isThru,0)

int WNWT_getput_diskblock_obj(PCACHE_ICTX ictx, ADDRESS addr, BYTE* data,BOOL isPut, BOOL isThru, size_t objSize)
{
	BOOL rtn=TRUE;
	cache_imp* cache = (cache_imp*)ictx->data;
	size_t devByteCnt = 1<<ictx->ctx->dev_ops.log2_blocksize;
	size_t cacheByteCnt = 1<<ictx->ctx->cache_ops.log2_blocksize;
	cached_data *mdataptr=NULL;
	cache_node* cnode;
	int i;
	int num_cache_ops;
	BOOL cleaningDirtyNode=FALSE;
	BOOL hitOrDirty=FALSE;

	DBG({dprintf("WNWT_getput_diskblock: addr:0x%08llx %s %s\n",addr,isPut?"WRITE":"READ",isThru?"THRU":"NONE");})

    if(ictx->ctx->use_object_interface)
    {
        devByteCnt = objSize; //make the object size the "block" size
    }

	/* check cache */

	/* calc num cacheops.read equal to disk blocksize / cache blocksize */
	num_cache_ops = 1;
	if(devByteCnt > cacheByteCnt)
	{
		num_cache_ops = (devByteCnt+(cacheByteCnt-1))/cacheByteCnt; //round up
	}
	else
	{
        /* this case is very untested XXX */
		/* make cacheReadCnt the smaller value */
		cacheByteCnt = devByteCnt;
	}

	DBG({dprintf("\t num_cache_ops:0x%02x devReadCnt:0x%08x cacheReadCnt:0x%08x\n",num_cache_ops,devByteCnt,cacheByteCnt);})


	/* look for address in internal cache */
	if(cache_retrieve_node(cache, &addr, &cnode))
	{
		mdataptr = cache_entry(cnode, cached_data, cnode);
		generic_mutex_lock(&mdataptr->lock); // lock if we get it
		if((void*)mdataptr->p == (void*)-1)
		{
			cleaningDirtyNode=TRUE;
		}

		hitOrDirty=TRUE;
		DBGL(1,{dprintf("\t cache %s: cnode:%p\n",cleaningDirtyNode?"DIRTY":"HIT",cnode);})
	}
	

	if(!hitOrDirty) /* if MISS */
	{
		BOOL gotEvictee;
        /* new node */
		if(!CACHEi_MakeCacheNode(ictx, &mdataptr, &gotEvictee) || mdataptr==NULL)
		{
	        DBG({dprintf("WNWT_getput_diskblock: MakeCacheNode failed\n");})
			return FALSE;
		}
		generic_mutex_lock(&mdataptr->lock); // lock if we make it
			
		if(!gotEvictee)
		{
			/* allocate cachedev blocks */
   			if(0!=DevOp(ictx, DEV_CACHE, &mdataptr->addr, cacheByteCnt*num_cache_ops, data, DEV_ALLOC))
			{
				if(mdataptr) cache_free(mdataptr);
	            DBG({dprintf("DevOp (alloc cachedev blocks) FAILED\n");})
				return FALSE;
			}
			DBG({dprintf("\t allocated cache_dev block @ 0x%08llx\n",mdataptr->addr);})
		}


        /* if read, make dirty true to reuse code path */
        if(!isPut) cleaningDirtyNode=TRUE;
    }

    /* reading */
    if(!isPut)
    {
        /* dirty (or new miss) */
        if(cleaningDirtyNode)
        {
            /* read primary */
            if(0!=DevOp(ictx, DEV_PRIMARY, &addr, devByteCnt, data, DEV_READ))
            {
	            DBG({dprintf("DevOp (read primary) FAILED\n");})
                rtn = FALSE;
            }
            /* write cache */
            if(rtn==FALSE || 0!=DevOp(ictx, DEV_CACHE, &mdataptr->addr, num_cache_ops*cacheByteCnt, data, DEV_WRITE))
            {
	            DBG({dprintf("DevOp (write cache) FAILED (or not tried)\n");})
                rtn = FALSE;
            }
            if(rtn==FALSE) 
            {
                /* error writing to cache, so mark as dirty */
		        mdataptr->p = (void*)-1;
            }
            else
            {
                /* mark not dirty */
    		    mdataptr->p = NULL;
            }
        }
        else /* valid hit */
        {
            /* read cache */
            if(0!=DevOp(ictx, DEV_CACHE, &mdataptr->addr, num_cache_ops*cacheByteCnt, data, DEV_READ))
            {
	            DBG({dprintf("DevOp (write cache) FAILED\n");})
                rtn = FALSE;
            }
        }
    }
    else /* writing */
    {
        void** completions=NULL; //for async ops MUST init to NULL

        if(!isThru) /* write none */
        {
            /* mark dirty */
		    mdataptr->p = (void*)-1;
        }
        else /* write thru */
        {
            /* if async support should do it here */
            int aret;
            aret = DevOpEx(ictx, DEV_CACHE, &mdataptr->addr, num_cache_ops*cacheByteCnt, data, DEV_AWRITE, &completions);
            if(aret==DEV_AWRITE_NOTSUPPORTED)
            { /* must do sync write */
            
            if(0!=DevOp(ictx, DEV_CACHE, &mdataptr->addr, num_cache_ops*cacheByteCnt, data, DEV_WRITE))
            {
                /* failed badly */
	            DBG({dprintf("DevOp (write cache) FAILED\n");})
                rtn=FALSE;
            }

            }
            else if(aret!=0) /* async write failed */
            {
	            DBG({dprintf("DevOp (async write cache) FAILED\n");})
                rtn=FALSE;
            }
           
            if(rtn==FALSE) 
            {
                /* error writing to cache, so mark as dirty */
		        mdataptr->p = (void*)-1;
            }
            else
            {
                /* mark not dirty */
    		    mdataptr->p = NULL;
            }
        }

        /* write primary (this can always be synchronous, or async and never wayt to complete, assuming back-end keeps consistency) */
        if(0!=DevOp(ictx, DEV_PRIMARY, &addr, devByteCnt, data, DEV_WRITE))
        {
            DBG({dprintf("DevOp (write primary) FAILED\n");})
            rtn = FALSE;
        }

        /* if cache async write support, complete here */
        if(completions!=NULL)
        {  /* async support available and there are things to complete! */
            if(0!=DevOpEx(ictx, DEV_CACHE, &mdataptr->addr, num_cache_ops*cacheByteCnt, data, DEV_AWRITE_WAITCOMPLETE, &completions))
            {
                DBG({dprintf("DevOp (write complete cache) FAILED\n");})
                rtn = FALSE;
            }
        }
        
    }

   	generic_mutex_unlock(&mdataptr->lock); //unlock since it's been held since retrieval/creation

    if(!hitOrDirty) /* was new node */
	{
        /* insert cache entry */
       	if(!cache_insert_node(cache,&addr,&mdataptr->cnode))
        	{
    			if(mdataptr) cache_free(mdataptr);
	            DBG({dprintf("cache_insert_node FAILED\n");})
    			return FALSE;
    	}
    }
    else /* old nodes need touch and release node */
    {
        if(!cache_touch_node(cache, &mdataptr->cnode))
        {
            DBG({dprintf("cache_touch_node FAILED\n");})
            return FALSE;
        }
      	if(!cache_release_node(cache, &mdataptr->cnode))
        {
            DBG({dprintf("cache_release_node FAILED\n");})
            return FALSE;
        }
    }

	return rtn;

}

#define WN_put_diskblock( ictx,  addr,  data) \
    WNWT_getput_diskblock(ictx,addr,data,TRUE,FALSE)

#define WT_put_diskblock( ictx,  addr,  data) \
    WNWT_getput_diskblock(ictx,addr,data,TRUE,TRUE)

#define WN_get_diskblock( ictx,  addr,  data) \
	WNWT_getput_diskblock(ictx, addr, data,FALSE,FALSE)

#define WT_get_diskblock( ictx, addr,   data) \
    WN_get_diskblock( ictx, addr, data)

/* obj interface */
#define WN_put_diskblockobj( ictx,  addr,  data, sz) \
    WNWT_getput_diskblock_obj(ictx,addr,data,TRUE,FALSE, sz)

#define WT_put_diskblockobj( ictx,  addr,  data, sz) \
    WNWT_getput_diskblock_obj(ictx,addr,data,TRUE,TRUE, sz)

#define WN_get_diskblockobj( ictx,  addr,  data, sz) \
	WNWT_getput_diskblock_obj(ictx, addr, data,FALSE,FALSE, sz)

#define WT_get_diskblockobj( ictx, addr,   data, sz) \
    WN_get_diskblockobj( ictx, addr, data, sz)

#define TEMPLATE_get(thetype,diskblock,dbobj)\
 TEMPLATE_getput(thetype,diskblock,0,dbobj)
#define TEMPLATE_put(thetype,diskblock,dbobj)\
 TEMPLATE_getput(thetype,diskblock,1,dbobj)

#define TEMPLATE_getput(thetype,diskblock,isWrite,diskblockobj)\
\
BOOL thetype(PCACHE_ICTX ictx, ADDRESS addr, BYTE* data, size_t sz) \
{ \
	size_t i; \
	size_t bs = (1ull<<ictx->ctx->dev_ops.log2_blocksize); \
	size_t l2bs = ictx->ctx->dev_ops.log2_blocksize; \
	ADDRESS startpage = addr & ~((ADDRESS)(bs-1)); \
	size_t startoffset = ((size_t)addr) & (bs-1); \
    ADDRESS endpage = (addr+(sz-1)) & ~((ADDRESS)(bs-1)); \
/*	size_t endoffset = ((size_t)(addr+(sz-1))) & (bs-1); */ \
	size_t exendoffset = ((size_t)(addr+(sz))) & (bs-1); \
/*    int fullblocks = (endpage/bs)-(startpage/bs)+1 \
         - (startoffset?1:0) - (exendoffset?1:0); \ */ \
    int startfpage = (startpage>>l2bs)+(startoffset?1:0); \
    int endfpage = (endpage>>l2bs)-(exendoffset?1:0); \
    int fullblocks = endfpage-startfpage+1; \
    size_t startblock=0;\
    ADDRESS base=startpage; \
    /* fullblocks might be negative after initial calc */ \
    if(fullblocks<0) fullblocks=0; \
\
	DBG({dprintf( #thetype ": addr:0x%08llx\n",addr);}) \
    \
	if(ictx->ctx->use_object_interface) \
    { /* assume only a single back-end call is neccessary and everything is aligned */ \
		if(0==diskblockobj(ictx,addr,data,sz)) return FALSE; \
        return TRUE; \
    } \
\
	if(startoffset!=0) \
	{ \
		size_t toCopy; \
		BYTE* buf = (BYTE*)cache_malloc(bs); \
		if(!buf) return FALSE; \
        DBG({dprintf("offset=%d calling early diskblock(FALSE,FALSE)\nbase:%08llx buf:%p",startoffset,startpage,buf);}) \
		if(0==WNWT_getput_diskblock(ictx,base,buf,FALSE,FALSE)) \
		{ \
			cache_free(buf); \
			return FALSE; \
		} \
		toCopy = bs-startoffset>sz?sz:bs-startoffset; \
        if(isWrite) {\
		    memcpy(buf+startoffset,data,toCopy); \
            DBG({dprintf("offset=%d calling early diskblock Write " #diskblock "\n",startoffset);}) \
    		if(0==diskblock(ictx,base,buf)) \
    		{ \
    			cache_free(buf); \
    			return FALSE; \
    		} \
        }\
        else\
            memcpy(data,buf+startoffset,toCopy);\
		cache_free(buf); \
		startblock=1; \
		sz-=toCopy; \
	} \
	for(i=startblock*bs;fullblocks>0;i+=bs,--fullblocks) \
	{ \
        DBG({dprintf("i=%u sz=%d fullblocks=%u calling normal " #diskblock "()\n",i,sz,fullblocks);})\
		if(0==diskblock(ictx,base+i,data-startoffset+i)) return FALSE; \
        sz-=bs; \
	} \
	if(exendoffset!=0 && sz>0) \
	{ \
		BYTE* buf = (BYTE*)cache_malloc(bs); \
		if(!buf) return FALSE; \
        DBG({dprintf("i=%d sz=%d eoff=%d calling late diskblock(FALSE,FALSE)\n",i,sz,exendoffset);})\
		if(0==WNWT_getput_diskblock(ictx,base+i,buf,FALSE,FALSE)) \
		{ \
			cache_free(buf); \
			return FALSE; \
		} \
        if(isWrite) {\
		    memcpy(buf,data-startoffset+i,exendoffset); \
            DBG({dprintf("offset=%d calling late diskblock Write " #diskblock "\n",exendoffset);}) \
    		if(0==diskblock(ictx,base,buf)) \
    		{ \
    			cache_free(buf); \
    			return FALSE; \
    		} \
        }\
        else\
            memcpy(data-startoffset+i,buf,exendoffset);\
		cache_free(buf); \
	} \
	return TRUE; \
}\


TEMPLATE_get(WN_get,WN_get_diskblock,WN_get_diskblockobj)
TEMPLATE_put(WN_put,WN_put_diskblock,WN_put_diskblockobj)
TEMPLATE_get(WT_get,WT_get_diskblock,WT_get_diskblockobj)
TEMPLATE_put(WT_put,WT_put_diskblock,WT_put_diskblockobj)



BOOL CACHEi_COMMON_defaultsize(PCACHE_CTX ctx, unsigned long long* sz)
{
	if(!sz) return FALSE;
	*sz=ctx->cache_ops.num_blocks;
	return TRUE;
}

CACHE_ERROR CACHEi_initCOMMON(PCACHE_CTX ctx,void* getfunc, void* putfunc, enum cache_imp_cachetype_e type)
{
	PCACHE_ICTX ictx = _PCACHE_ICTX(ctx);
	unsigned long long size;

	ictx->get			=(ictx_get) getfunc;
	ictx->put			=(ictx_put) putfunc;

	if(!CACHEi_COMMON_defaultsize(ctx,&size))
	{
		return CACHE_ERROR_internalerror;
	}

	/* initialize COMMON data structure */
	ictx->data = cache_malloc(sizeof(cache_imp));
	cache_imp_init((cache_imp*)ictx->data,size,type);

	return CACHE_ERROR_success;
}

CACHE_ERROR CACHEi_destroyCOMMON(PCACHE_CTX ctx)
{
	PCACHE_ICTX ictx = _PCACHE_ICTX(ctx);

	if(!cache_imp_fini((cache_imp*)ictx->data)) return CACHE_ERROR_internalerror;
	cache_free(ictx->data);

	return CACHE_ERROR_success;
}

/* Write None Cache */
CACHE_ERROR CACHEi_initWNLRU(PCACHE_CTX ctx)
{
	return CACHEi_initCOMMON(ctx,WN_get,WN_put,cache_imp_cachetype_LRU);
}

CACHE_ERROR CACHEi_destroyWNLRU(PCACHE_CTX ctx)
{
	return CACHEi_destroyCOMMON(ctx);
}

CACHE_ERROR CACHEi_initWNMRU(PCACHE_CTX ctx)
{
	return CACHEi_initCOMMON(ctx,WN_get,WN_put,cache_imp_cachetype_MRU);
}

CACHE_ERROR CACHEi_destroyWNMRU(PCACHE_CTX ctx)
{
	return CACHEi_destroyCOMMON(ctx);
}

/* Write Thru Cache */
CACHE_ERROR CACHEi_initWTLRU(PCACHE_CTX ctx)
{
	return CACHEi_initCOMMON(ctx,WT_get,WT_put,cache_imp_cachetype_LRU);
}

CACHE_ERROR CACHEi_destroyWTLRU(PCACHE_CTX ctx)
{
	return CACHEi_destroyCOMMON(ctx);
}

CACHE_ERROR CACHEi_initWTMRU(PCACHE_CTX ctx)
{
	return CACHEi_initCOMMON(ctx,WT_get,WT_put,cache_imp_cachetype_MRU);
}

CACHE_ERROR CACHEi_destroyWTMRU(PCACHE_CTX ctx)
{
	return CACHEi_destroyCOMMON(ctx);
}


//////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////


/* /internal api */

/* exposed api */
#define CACHE_SUCCESS(ctx) ((ctx)->error==CACHE_ERROR_success?TRUE:FALSE)
#define CACHE_NOERROR(err) ((err)==CACHE_ERROR_success?TRUE:FALSE)

/* initialize a new cache */
BOOL CACHE_init(PCACHE_CTX ctx,CACHE_TYPE type)
{
	if(!ctx) return FALSE;
	if(!CACHE_NOERROR(ctx->error=CACHEi_validatectx(ctx))) return FALSE;
	ctx->error=CACHE_ERROR_success;

	if(!CACHE_NOERROR(ctx->error=CACHEi_initdefault(ctx))) return FALSE;

	switch(type)
	{
	case CACHE_TYPE_default:
		//break; // default type is WN_LRU
	case CACHE_TYPE_WN_LRU:
		if(!CACHE_NOERROR(ctx->error=CACHEi_initWNLRU(ctx))) break;
		break;
	case CACHE_TYPE_WN_MRU:
		if(!CACHE_NOERROR(ctx->error=CACHEi_initWNMRU(ctx))) break;
		break;
	case CACHE_TYPE_WT_LRU:
		if(!CACHE_NOERROR(ctx->error=CACHEi_initWTLRU(ctx))) break;
		break;
	case CACHE_TYPE_WT_MRU:
		if(!CACHE_NOERROR(ctx->error=CACHEi_initWTMRU(ctx))) break;
		break;
	default:
		ctx->error=CACHE_ERROR_unknowntype; return FALSE;
		break;
	};
	return (CACHE_SUCCESS(ctx));
}

/* free a cache */
BOOL CACHE_destroy(PCACHE_CTX ctx)
{
	if(!ctx) return FALSE;
	if(!CACHE_NOERROR(ctx->error=CACHEi_validatectx(ctx))) return FALSE;
	ctx->error=CACHE_ERROR_success;
	switch(ctx->type)
	{
	case CACHE_TYPE_default:
		//break; // default type is WN_LRU
	case CACHE_TYPE_WN_LRU:
		if(!CACHE_NOERROR(ctx->error=CACHEi_destroyWNLRU(ctx))) break;
		break;
	case CACHE_TYPE_WN_MRU:
		if(!CACHE_NOERROR(ctx->error=CACHEi_destroyWNMRU(ctx))) break;
		break;
	case CACHE_TYPE_WT_LRU:
		if(!CACHE_NOERROR(ctx->error=CACHEi_destroyWTLRU(ctx))) break;
		break;
	case CACHE_TYPE_WT_MRU:
		if(!CACHE_NOERROR(ctx->error=CACHEi_destroyWTMRU(ctx))) break;
		break;
	default:
		ctx->error=CACHE_ERROR_unknowntype; return FALSE;
	};
	ctx->error=CACHEi_destroydefault(ctx);
	return (CACHE_SUCCESS(ctx));
}

BOOL CACHE_get(PCACHE_CTX ctx, ADDRESS addr, BYTE* data, size_t sz)
{
	if(!ctx) return FALSE;
	if(!CACHE_NOERROR(ctx->error=CACHEi_validatectx(ctx))) return FALSE;
	if(!CACHE_NOERROR(ctx->error=CACHEi_validateictx(ctx))) return FALSE;

	{
		PCACHE_ICTX ictx = _PCACHE_ICTX(ctx);
		ctx->error = CACHE_ERROR_internalerror;
		if(!ictx->get(ictx,addr,data,sz)) return FALSE;
		ctx->error = CACHE_ERROR_success;
	}
	
	return TRUE;
}

BOOL CACHE_put(PCACHE_CTX ctx, ADDRESS addr, BYTE* data, size_t sz)
{
	if(!ctx) return FALSE;
	if(!CACHE_NOERROR(ctx->error=CACHEi_validatectx(ctx))) return FALSE;
	if(!CACHE_NOERROR(ctx->error=CACHEi_validateictx(ctx))) return FALSE;

	{
		PCACHE_ICTX ictx = _PCACHE_ICTX(ctx);
		ctx->error = CACHE_ERROR_internalerror;
		if(!ictx->put(ictx,addr,data,sz)) return FALSE;
		ctx->error = CACHE_ERROR_success;
	}
	
	return TRUE;
}


/* /exposed api */


#ifndef __KERNEL__
/* testing */
//////////////////////////////////////////////////////////////////////

BOOL disk_write(unsigned long long address, BYTE* data, size_t sz)
{
	printf("disk_write 0x%08llx %02x ... 0x%08x\n",address,data[0],sz);
	return TRUE;
}
BOOL disk_read(unsigned long long address, BYTE* data, size_t* sz)
{
	size_t i;
	for(i=0;i<*sz;++i) data[i]=(BYTE)i;
	printf("read 0x%08llx %02x ... 0x%08x\n",address,data[0],*sz);
	return TRUE;
}
BOOL disk_alloc(unsigned long long* address, size_t sz)
{
	printf("disk_alloc 0x%08llx 0x%08x\n",(*address),sz);
	return TRUE;
}
/*
#ifndef WIN32
BOOL odisk_write(void* arg, ADDRESS address, BYTE* data, size_t sz) { return disk_write(((unsigned long)arg)+address.lu,data,sz); }
BOOL odisk_read(void* arg, ADDRESS address, BYTE* data, size_t* sz) { return disk_read(((unsigned long)arg)+address.lu,data,sz); }
BOOL odisk_alloc(void* arg, ADDRESS* address, size_t sz) { return disk_alloc(((unsigned long long*)arg)+address->lu,sz); }
#else
BOOL odisk_write(void* arg, ADDRESS address, BYTE* data, size_t sz) { return disk_write(((unsigned long long)arg)+address,data,sz); }
BOOL odisk_read(void* arg, ADDRESS address, BYTE* data, size_t sz) { return disk_read(((unsigned long long)arg)+address,data,sz); }
BOOL odisk_alloc(void* arg, ADDRESS* address, size_t sz) { return disk_alloc(((unsigned long long*)arg)+address,sz); }
#endif
*/

typedef struct buffer_st {
	void* data;
	unsigned long long length;
	unsigned char log2_blocksize;
	unsigned long long numblocks;
	unsigned long long allocated;
} buffer_t, *pbuffer;

#define HAVESLEEP
#ifndef HAVESLEEP
#ifdef WIN32
#define SLEEP(x) _sleep(x*1000)
#else
#include<unistd.h>
#define SLEEP(x) sleep(x)
#endif
#else
//#define SLEEP(x) sleep(x)
#define SLEEP(x)
#endif

int mdisk_write(void* arg, ADDRESS address, BYTE* data, size_t sz)
{
	DBG({dprintf("mdisk_write arg:%p addr:0x%08llx\n",arg,address);})
	SLEEP(2);
	if(address+sz > ((pbuffer)arg)->length) return -1;
	memcpy((BYTE*)(((pbuffer)arg)->data)+address, data,sz);
	return 0;
}
int mdisk_read(void* arg, ADDRESS address, BYTE* data, size_t sz) {
	DBG({dprintf("mdisk_read arg:%p addr:0x%08llx\n",arg,address);})
	SLEEP(1);
	if(address+sz > ((pbuffer)arg)->length) return FALSE;
	memcpy(data, (BYTE*)(((pbuffer)arg)->data)+address, sz);
	return 0;
}
int mdisk_alloc(void* arg, ADDRESS* address, size_t sz) {
	//<FIX>
	//((pbuffer)arg)->numblocks
	unsigned long long i=((pbuffer)arg)->allocated;
	unsigned long long bs = 1ull<< ((pbuffer)arg)->log2_blocksize;
	DBG({dprintf("mdisk_alloc arg:%p ret:%llx sz:%x\n",arg,i,sz);})

	*address=i;
//    sz = (sz+(bs-1))/bs; //round up num of blocks
	i+=sz*bs;
	((pbuffer)arg)->allocated=i;
	return 0;
}
int mdisk_free(void* arg, ADDRESS address, size_t sz) {
	//<FIX>
	return 0;
}
int mdisk_asyncwrite(void* arg, ADDRESS address, BYTE* data, size_t sz, void* context, void (*callback)(void*,int))
{
	int rtn = mdisk_write(arg,address,data,sz);
	if(!callback) return -1;
	callback(context,rtn);
	return 0;
}

void test_get_int(CACHE_CTX* ctx,int iaddr)
{
	printf("\t\tGET %d\n",iaddr);
	{
		int x=iaddr; BOOL rtn;
		ADDRESS addr = iaddr*(1<<ctx->dev_ops.log2_blocksize);
		printf("test_get_int( 0x%016llx )",addr);
		rtn = CACHE_get(ctx,addr,(BYTE*)&x,sizeof(x));
		printf("test_get_int:GOT( 0x%08x )\n",x);
	}
}
void test_put_int(CACHE_CTX* ctx,int iaddr)
{
	printf("\t\tPUT %d\n",iaddr);
	{
		int x=iaddr+0x1000; BOOL rtn;
		ADDRESS addr = iaddr*(1<<ctx->dev_ops.log2_blocksize);
		printf("test_put_int( 0x%016llx )\n",addr);
		rtn = CACHE_put(ctx,addr,(BYTE*)&x,sizeof(x));
	}
}
void test_store_int(CACHE_CTX* ctx,int iaddr)
{
	printf("\t\tSTORE %d\n",iaddr);
	{
		int x=iaddr; BOOL rtn;
		ADDRESS addr = iaddr*(1<<ctx->dev_ops.log2_blocksize);
		rtn = 0==ctx->dev_ops.write(ctx->dev_ops.opaque_data,addr,(BYTE*)&x,sizeof(x));
	}
}

int test1(int argc, char* argv[])
{
	return 0;
}

#include<time.h>
int main(int argc, char* argv[])
{
	clock_t t1;
	clock_t t2;

/* create "ram disk" for underlying device */
	const unsigned char under_disk_log2_blocksize = 9;
	const unsigned long long under_disk_numblocks = 0x10000/(1<<under_disk_log2_blocksize);
	const unsigned long long under_disk_size = under_disk_numblocks << under_disk_log2_blocksize;
	void* under_disk = malloc((unsigned int)under_disk_size);
	buffer_t under_buf = {under_disk,under_disk_size,under_disk_log2_blocksize,under_disk_numblocks,0};
/* create "ram disk" for cache device */
	const unsigned char cache_disk_log2_blocksize = 4;
	const unsigned long long cache_disk_numblocks = 0x1000/(1<<cache_disk_log2_blocksize);
	const unsigned long long cache_disk_size = cache_disk_numblocks << cache_disk_log2_blocksize;
	void* cache_disk = malloc((unsigned int)cache_disk_size);
	buffer_t cache_buf = {cache_disk,cache_disk_size,cache_disk_log2_blocksize,cache_disk_numblocks,0};

#ifndef WIN32
	/*
	CACHE_CTX ctx = {
		0,0,{
			.malloc = malloc,
			.free=free,
			.realloc=realloc
		},
		{
			.read=mdisk_read,
			.write=mdisk_write,
			.alloc=NULL,//mdisk_alloc,
			.free=NULL,
			&under_buf,
			under_disk_log2_blocksize,
			under_disk_numblocks
		},
		{
			.read=mdisk_read,
			.write=mdisk_write,
			.alloc=mdisk_alloc,
			.free=mdisk_free,
			&cache_buf,
			cache_disk_log2_blocksize,
			cache_disk_numblocks
		},
		0,0
	};
	*/
		CACHE_CTX ctx = {
		0,0,
		{
			malloc,
			free,
			realloc
		},
		{
			mdisk_read,
			mdisk_write,
			NULL,//mdisk_alloc,
			NULL,
			&under_buf,
			under_disk_log2_blocksize,
			under_disk_numblocks,
			FALSE,
			NULL,
            NULL
		},
		{
			mdisk_read,
			mdisk_write,
			mdisk_alloc,
			mdisk_free,
			&cache_buf,
			cache_disk_log2_blocksize,
			cache_disk_numblocks,
			FALSE,//TRUE,
			NULL,//mdisk_asyncwrite
            NULL
		},
		0,0,0
	};

#else
	CACHE_CTX ctx = {
		0,0,
		{
			malloc,
			free,
			realloc
		},
		{
			mdisk_read,
			mdisk_write,
			NULL,//mdisk_alloc,
			NULL,
			&under_buf,
			under_disk_log2_blocksize,
			under_disk_numblocks,
			FALSE,
			NULL,
            NULL
		},
		{
			mdisk_read,
			mdisk_write,
			mdisk_alloc,
			mdisk_free,
			&cache_buf,
			cache_disk_log2_blocksize,
			cache_disk_numblocks,
			FALSE,//TRUE,
			NULL,//mdisk_asyncwrite
            NULL
		},
		0,0,0
	};
#endif

    { /* printf testing! */
	DBG({dprintf("TEST: dprintf inside DBG\n");})
	DBGL(1,{dprintf("TEST: dprintf inside DBGL(1)\n");})
	dprintf("TEST: dprintf only\n");
    printf("TEST: printf only DEBUGLEVEL=%d\n",DEBUGLEVEL);
    }

    /* aligned normal-sized simple put/get test */
	{
		BOOL rtn = CACHE_init(&ctx,0);
		cache_buf.allocated=0;
		printf("CACHE_init: %d error: %s\n",rtn,CACHE_ERROR2STR(ctx.error));
		if(!rtn) exit(0);
	}

	{
		unsigned int i;
		BYTE str[0x10] = "0123456789HELLO";
        BYTE* buf;
		size_t bufsz = 1<<ctx.dev_ops.log2_blocksize;
		BOOL rtn;
        buf = malloc(bufsz);
        if(!buf) { printf("ERROR: malloc ctx.dev_ops.log2_blocksize=%d FAILED\n",ctx.dev_ops.log2_blocksize); return -1;}
        memcpy(buf,str,strlen(str));
		for(i=0;i<1;i+=0x1) {
			ADDRESS addr = {i};
//			*(unsigned int*)buf=i;
			rtn = CACHE_put(&ctx,addr+i*ctx.dev_ops.log2_blocksize,buf,bufsz);
			printf("CACHE_put: %d error: %s\n",rtn,CACHE_ERROR2STR(ctx.error));
		}
        free(buf);
	}

	t1=clock();
	{
		size_t bufsz = 1<<ctx.dev_ops.log2_blocksize;
        BYTE* buf = malloc(bufsz);
        if(!buf) { printf("ERROR: malloc ctx.dev_ops.log2_blocksize=%d FAILED\n",ctx.dev_ops.log2_blocksize); return -1;}
		ADDRESS addr = {0};
		BOOL rtn = CACHE_get(&ctx,addr,buf,bufsz);
		printf("CACHE_get: %d error: %s\n",rtn,CACHE_ERROR2STR(ctx.error));
		printf("buf = %s\n",buf);
        if(strcmp(buf,"0123456789HELLO")!=0) {
            printf("FATAL CACHE ERROR on REALLY simple put/get!!!\n");
            exit(-1);
        } else
            printf("CACHE GOOD on REALLY simple put/get!!!\n");
        free(buf);
	}

    /* unaligned wierd sized, orginal test 1 */
	{
		BOOL rtn = CACHE_init(&ctx,0);
		cache_buf.allocated=0;
		printf("CACHE_init: %d error: %s\n",rtn,CACHE_ERROR2STR(ctx.error));
		if(!rtn) exit(0);
	}

	{
		unsigned int i;
		BYTE buf[0x10] = "0123456789HELLO";
		size_t bufsz = 0x10;
		BOOL rtn;
		for(i=0;i<0x20/*under_buf.length*/;i+=0x10) {
			ADDRESS addr = {i};
			*(unsigned int*)buf=i;
			rtn = CACHE_put(&ctx,addr,buf,bufsz);
			printf("CACHE_put: %d error: %s\n",rtn,CACHE_ERROR2STR(ctx.error));
		}
	}

	t1=clock();
	{
#define bufallocsz 6
		size_t bufsz = bufallocsz;
		BYTE buf[bufallocsz];
		ADDRESS addr = {10};
		BOOL rtn = CACHE_get(&ctx,addr,buf,bufsz);
		printf("CACHE_get: %d error: %s\n",rtn,CACHE_ERROR2STR(ctx.error));
		printf("buf = %s\n",buf);
        if(strcmp(buf,"HELLO")!=0) {
            printf("FATAL CACHE ERROR on simple put/get!!!\n");
            exit(-1);
        }
	}
	t2=clock();
	printf("t diff: 0x%08x / 0x%08x\n",(unsigned int)(t2-t1),(unsigned int)CLOCKS_PER_SEC);

	if(0){
		BYTE buf[0x10];
		ADDRESS a;
		int j;
		printf("mdisk disk_dev values at addresses\n");
		for(a=0;a<0x200;a+=0x10)
		{
			mdisk_read(&cache_buf,a,buf,0x10);
			for(j=0;j<0x10;++j) {
				printf("%02x ",buf[j]);
			}
			printf("\n");
		}
	}

	t1=clock();
	{
//#define bufallocsz 6
		size_t bufsz = bufallocsz;
		BYTE buf[bufallocsz];
		ADDRESS addr = {10};
		BOOL rtn = CACHE_get(&ctx,addr,buf,bufsz);
		printf("AGAIN CACHE_get: %d error: %s\n",rtn,CACHE_ERROR2STR(ctx.error));
		printf("AGAIN buf = %s\n",buf);
	}
	t2=clock();
	printf("t diff: 0x%08x / 0x%08x\n",(unsigned int)(t2-t1),(unsigned int)CLOCKS_PER_SEC);


	{
		BOOL rtn = CACHE_destroy(&ctx);
		printf("CACHE_destroy: %d error: %s\n",rtn,CACHE_ERROR2STR(ctx.error));
		if(!rtn) exit(0);
	}


/////////////////////////////////////////////////////////
	if(1){
		int i;
		for(i=0;i<10;++i)
			test_store_int(&ctx,i);
	}

	/* testing WN get */
	printf("-----------------------------------------------------------------------------\n");
	printf("TESTING Write None LRU gets\n");
	ctx.cache_ops.num_blocks=5;
	{
		BOOL rtn = CACHE_init(&ctx,0);
		cache_buf.allocated=0;
		printf("CACHE_init: %d error: %s\n",rtn,CACHE_ERROR2STR(ctx.error));
		if(!rtn) exit(0);
	}

	test_get_int(&ctx,1);
	test_get_int(&ctx,2);
	test_get_int(&ctx,3);
	test_get_int(&ctx,4);
	test_get_int(&ctx,5);
	test_get_int(&ctx,1);
	test_get_int(&ctx,2);
	test_get_int(&ctx,7);
	test_get_int(&ctx,3);
	test_get_int(&ctx,7);


	{
		BOOL rtn = CACHE_destroy(&ctx);
		printf("CACHE_destroy: %d error: %s\n",rtn,CACHE_ERROR2STR(ctx.error));
		if(!rtn) exit(0);
	}

	/* testing WN put */
	printf("-----------------------------------------------------------------------------\n");
	printf("TESTING Write None LRU puts\n");
	ctx.cache_ops.num_blocks=5;
	{
		BOOL rtn = CACHE_init(&ctx,0);
		cache_buf.allocated=0;
		printf("CACHE_init: %d error: %s\n",rtn,CACHE_ERROR2STR(ctx.error));
		if(!rtn) exit(0);
	}

	test_get_int(&ctx,1);
	test_get_int(&ctx,2);
	test_get_int(&ctx,1);

	test_get_int(&ctx,1);
	test_get_int(&ctx,2);
	test_get_int(&ctx,3);
	test_put_int(&ctx,2);
	test_get_int(&ctx,1);
	test_get_int(&ctx,2);
	test_get_int(&ctx,3);


	{
		BOOL rtn = CACHE_destroy(&ctx);
		printf("CACHE_destroy: %d error: %s\n",rtn,CACHE_ERROR2STR(ctx.error));
		if(!rtn) exit(0);
	}

	/* testing WT put */
	printf("-----------------------------------------------------------------------------\n");
	printf("TESTING Write Thru LRU\n");
		ctx.cache_ops.num_blocks=5;
	{
		BOOL rtn = CACHE_init(&ctx,CACHE_TYPE_WT_LRU);
		cache_buf.allocated=0;
		printf("CACHE_init: %d error: %s\n",rtn,CACHE_ERROR2STR(ctx.error));
		if(!rtn) exit(0);
	}

	test_get_int(&ctx,1);
	test_get_int(&ctx,2);
	test_get_int(&ctx,1);

	test_get_int(&ctx,1);
	test_get_int(&ctx,2);
	test_get_int(&ctx,3);
	test_put_int(&ctx,2);
	test_get_int(&ctx,1);
	test_get_int(&ctx,2);
	test_get_int(&ctx,3);


	{
		BOOL rtn = CACHE_destroy(&ctx);
		printf("CACHE_destroy: %d error: %s\n",rtn,CACHE_ERROR2STR(ctx.error));
		if(!rtn) exit(0);
	}
	return 0;
}
#endif //ifndef __KERNEL__

