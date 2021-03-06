#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/sched.h>
#include <linux/kernel.h>	/* printk() */
#include <linux/slab.h>		/* kmalloc() */
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */

#include <linux/blkdev.h>

/* Everything */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/wait.h>
#include <linux/blkdev.h>
#include <linux/blkpg.h>
#include <linux/init.h>
#include <linux/smp_lock.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/loop.h>
#include <linux/compat.h>
#include <linux/suspend.h>
#include <linux/freezer.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h>		/* for invalidate_bdev() */
#include <linux/completion.h>
#include <linux/highmem.h>
#include <linux/gfp.h>
#include <linux/kthread.h>

#include <linux/hdreg.h>	/* HDIO_GETGEO */
#include <linux/completion.h>

#include "../Cache/Cache/Cache.h"

#ifdef BB_DEBUG
#define dprintk(a...) printk(a)
#else
#define dprintk(a...)
#endif

#ifdef BB_NO_OUTPUT
#define printk(a...)
#endif

#include <asm/uaccess.h>

MODULE_LICENSE("Dual BSD/GPL");

static int bb_major = 0;
module_param(bb_major, int, 0);

/* XXX */
static int hardsect_size = 512; /* Varies by underlying device */
#define KERNEL_SECTOR_SIZE	512
module_param(hardsect_size, int, 0);
static int nsectors = 1024;	/* How big the drive is */
module_param(nsectors, int, 0);

static int ndevices = 4;
module_param(ndevices, int, 0);

static int BB_KERNEL_SCRATCH_LEN = 16384;

DECLARE_COMPLETION(dup_write_complete);

struct bb_seq_req {
	struct bb_device *bb;
	int seq;
	struct bio *bio_dup;
};

/* See /usr/src/linux/include/linux/loop.h */
struct bb_device {
	int bb_number;
	int bb_refcnt;
	spinlock_t		bb_lock;
	struct mutex bb_ctl_mutex;
	struct gendisk *bb_disk;
	struct task_struct	*bb_thread; /* XXX unrefrenced? */
	wait_queue_head_t	bb_event; /* XXX unrefrenced? */
	struct request_queue	*bb_queue; /* Our own queue */

	int backing_cnt;
	struct block_device     *bdev_a;
	struct request_queue    *bb_backing_queue_a;
	struct block_device     *bdev_b;
	struct request_queue    *bb_backing_queue_b;

	struct bb_seq_req bb_bio_seq[256];
	int bb_bio_seq_cnt;

	unsigned char *kbuf; /* For converting to and from bio. */
	unsigned int kbuf_len;
	struct CACHE_CTX_st *ctx;
#ifdef SIMPLE_LOCKS
    struct mutex cache_lock;
#endif
};


/* ----------- CACHE glue ------------*/

/* this struct is being used as the opaque data for accessing the
 * underlying devices
 */
struct bb_underdisk {
    /* for device access by Cache code */
	struct bb_device *bb;
	struct block_device *bdev;
	struct request_queue *q;
    /* for Cache code sector allocation */
    unsigned long long next_free_sector;
    unsigned int log2_blocksize;
};
/* this struct is used for the opaque data sent to the end_io
 * completion routines for synchronous reads and writes
 */
struct bio_readwrite_args {
    /* for completion */
	bio_end_io_t* old_endio;
	struct completion* c;
};

static void* kmalloc_wrapper(size_t sz)
{
    return kmalloc(sz,GFP_KERNEL);
}
static void kfree_wrapper(void* p)
{
    if(p) //extra safety check (might slow things down?)
        kfree(p);
}
static void* krealloc_wrapper(void* p, size_t newsz)
{
    void* n;
    if((n=kmalloc_wrapper(newsz))==NULL) return NULL;
    kfree_wrapper(p);
    return(n);
}
static int bb_sync_sector_read(void *opaque, ADDRESS address, BYTE* data, size_t sz);
static int bb_sync_sector_write(void *opaque, ADDRESS address, BYTE* data, size_t sz);
static int bb_async_sector_write(void *opaque, ADDRESS address, BYTE* data, size_t sz, void** ppcompletion);
static int bb_async_sector_write_waitcomplete(void *opaque, ADDRESS address, BYTE* data, size_t sz, void* ppcompletion);

static int bb_sector_alloc(void* arg, ADDRESS* address, size_t sz) {
    struct bb_underdisk* d = (struct bb_underdisk*)arg;
	*address =(d->next_free_sector)<<d->log2_blocksize;
    d->next_free_sector+=sz;
	return 0;
}

/* never really free a sector since allocate is just a 1-up counter */
static int bb_sector_free_NOP(void* opaque, ADDRESS address, size_t sz) { return 0;}

static CACHE_CTX g_CACHE_CTX_TEMPLATE = {
		0,0,
		{
			kmalloc_wrapper,
			kfree_wrapper,
			krealloc_wrapper // no realloc in kernel, but this is never used! (should be removed)
		},
		{
			bb_sync_sector_read,
			bb_sync_sector_write,
			NULL,//mdisk_alloc,
			NULL,
			NULL,//&under_buf,
			9,//under_disk_log2_blocksize, /* ALWAYS 512 */
			0,//under_disk_numblocks,
			FALSE,
			NULL,
            NULL
		},
		{
			bb_sync_sector_read,
			bb_sync_sector_write,
			bb_sector_alloc,//mdisk_alloc,
			bb_sector_free_NOP,//mdisk_free, /* used only if write fails */
			NULL,//&cache_buf,
			9,//cache_disk_log2_blocksize, /* ALWAYS 512 */
			0,//cache_disk_numblocks,
#ifdef BB_CACHE_ASYNCWRITES
			TRUE,
			bb_async_sector_write,
            bb_async_sector_write_waitcomplete
#else
			FALSE,//TRUE,
            NULL,
            NULL
#endif
		},
		0,0
#ifdef TRY_NO_DOUBLEBUFFER
,1 /* set object interface */
#else
,0 /* normal (old) buffer interface */
#endif
	};

/* END -------------- Cache glue ------------------------- */

static struct bb_device **Devices = NULL;

/* Forward declarations */
static int bb_open(struct inode *inode, struct file *file);
static int bb_release(struct inode *inode, struct file *file);
static int bb_ioctl(struct inode * inode, struct file * file,
		    unsigned int cmd, unsigned long arg);

static int bb_make_request(struct request_queue *q, struct bio *bio);
static int bb_handle_bio(struct bb_device *bb, struct bio *bio);
static int bb_xfer_bio(struct bb_device*dev, struct bio *bio);
static int bb_bio_end_io(struct bio *bio, unsigned int bytes, int status);
static int bb_dup_bio_end_io(struct bio *bio, unsigned int bytes, int status);

static void copybio2kern(struct bio *bio, unsigned char* kaddr, unsigned int klen);
static void copykern2bio(struct bio *bio, unsigned char* kaddr, unsigned int klen);

static struct block_device_operations bb_fops = {
	.owner =	THIS_MODULE,
	.open =		bb_open,
	.release =	bb_release,
	.ioctl =	bb_ioctl,
};


static struct bb_device *bb_alloc(int i)
{
	struct bb_device *bb;
	struct gendisk *disk;

	bb = kzalloc(sizeof(*bb), GFP_KERNEL);
	if (!bb)
		goto out;

	bb->kbuf = kzalloc(BB_KERNEL_SCRATCH_LEN, GFP_KERNEL);

	if (!bb->kbuf) {
		goto out;
	}
	bb->kbuf_len = BB_KERNEL_SCRATCH_LEN;

	bb->bb_queue = blk_alloc_queue(GFP_KERNEL);

	if (!bb->bb_queue)
		goto out_free_dev;

	blk_queue_make_request(bb->bb_queue, bb_make_request);

	/* XXX blk_queue_hardsect_size */
	blk_queue_hardsect_size(bb->bb_queue, hardsect_size);

	/* This is very inefficient - only supports requests of one
	 * sector at a time.
	 */

	blk_queue_max_sectors(bb->bb_queue, 1);

	bb->bb_queue->queuedata = bb;

	disk = bb->bb_disk = alloc_disk(1);
	if (!disk)
		goto out_free_queue;

	mutex_init(&bb->bb_ctl_mutex);
	bb->bb_number		= i;
	bb->bb_thread		= NULL;
	init_waitqueue_head(&bb->bb_event);
	spin_lock_init(&bb->bb_lock);
	disk->major		= bb_major;
	disk->first_minor	= i;
	disk->fops		= &bb_fops;
	disk->private_data	= bb;
	disk->queue		= bb->bb_queue;
	sprintf(disk->disk_name, "bb%d", i);

	/* Initially set the capacity to 0 -- will be adjusted when
	 * backing devices are added.
	 */
	set_capacity(disk, 0);
	add_disk(disk);

	for (i=0; i<sizeof(bb->bb_bio_seq)/sizeof(bb->bb_bio_seq[0]); i++) {
		bb->bb_bio_seq[i].bb = bb;
		bb->bb_bio_seq[i].seq = i;
	}
	bb->bb_bio_seq_cnt = 0;

	return bb;

out_free_queue:
	blk_cleanup_queue(bb->bb_queue);
out_free_dev:
	kfree(bb);
out:
	return NULL;
}

static void bb_free(struct bb_device *bb)
{
	dprintk (KERN_WARNING "bb: bb_free entered\n");

	blk_cleanup_queue(bb->bb_queue);
	del_gendisk(bb->bb_disk);
	put_disk(bb->bb_disk);
	kfree(bb);

	dprintk (KERN_WARNING "bb: bb_free exited\n");
}
#define mymax(a,b) ((a)>(b)?(a):(b))
static unsigned int mylog2(unsigned int s)
{
    int i,j=-1;
    for(i=0;i<32;++i)
    {
        if(s & (1<<i))
        {
            if(j!=-1)
            {
                return mymax(j,0);
            }
            j=i;
        }
    }
    if(j<0) j=0;
    return mymax((unsigned int)j,0);
}

static int bb_set_fd(struct bb_device *bb,
		     unsigned int arg)
{
	int error;
	struct file *file;
	struct inode *inode;
	struct block_device *backing_dev;
	struct request_queue *backing_queue;

	error = -EBADF;

    /* if we have both devices, this should set the cache type */
	if (bb->backing_cnt == 2) {
#ifndef DISABLE_CACHE
        // if we already had a cache, destroy it and free memory
        if(bb->ctx) {
#ifdef SIMPLE_LOCKS
            mutex_lock(&bb->cache_lock);
#endif
            CACHE_destroy(bb->ctx); 
            kfree(bb->ctx);
            bb->ctx = NULL;
#ifdef SIMPLE_LOCKS
            mutex_unlock(&bb->cache_lock);
#endif
        }

        /* Initialize Cache implementation for bb */
        bb->ctx = kzalloc(sizeof(*bb->ctx),GFP_KERNEL);
        if(!bb->ctx) {
	    	dprintk (KERN_WARNING "bb: cant allocate bb->ctx\n");
            /* XXX should probably change error code */
	    	goto out;
	    }
        memcpy(bb->ctx,&g_CACHE_CTX_TEMPLATE,sizeof(*bb->ctx));
        /* secific initialization */
        /* dev_ops init */
        bb->ctx->dev_ops.log2_blocksize=3+mylog2(bdev_hardsect_size(bb->bdev_a));
        bb->ctx->dev_ops.num_blocks=get_capacity(bb->bdev_a->bd_disk)
		>> (bb->ctx->dev_ops.log2_blocksize-9);
	#ifdef BB_FORCE_MAX_CAPACITY
        if(bb->ctx->dev_ops.num_blocks > 2*1024*BB_FORCE_MAX_CAPACITY)
		bb->ctx->dev_ops.num_blocks = 2*1024*BB_FORCE_MAX_CAPACITY;
	#endif
        bb->ctx->dev_ops.opaque_data = kzalloc(sizeof(struct bb_underdisk),GFP_KERNEL);
        if(!bb->ctx->dev_ops.opaque_data) {
	    	dprintk (KERN_WARNING "bb: cant allocate bb->ctx->dev_ops.opaque_data\n");
            /* XXX should probably change error code */
	    	goto out;
        }
        {
        struct bb_underdisk* d = 
            (struct bb_underdisk*)bb->ctx->dev_ops.opaque_data;
        d->bb=bb;
        d->bdev=bb->bdev_a;
        d->q=bb->bb_backing_queue_a;
        d->log2_blocksize=bb->ctx->dev_ops.log2_blocksize;
	printk(KERN_WARNING"bb: primary log2_blocksize=%d\n",d->log2_blocksize);
        }
        /* cache_ops init */
        bb->ctx->cache_ops.log2_blocksize=3+mylog2(bdev_hardsect_size(bb->bdev_b));
        bb->ctx->cache_ops.num_blocks=get_capacity(bb->bdev_b->bd_disk)
		>> (bb->ctx->cache_ops.log2_blocksize-9);
	#ifdef BB_FORCE_MAX_CAPACITY
        if(bb->ctx->cache_ops.num_blocks > 2*1024*BB_FORCE_MAX_CAPACITY)
		bb->ctx->cache_ops.num_blocks = 2*1024*BB_FORCE_MAX_CAPACITY;
	#endif
        bb->ctx->cache_ops.opaque_data = kzalloc(sizeof(struct bb_underdisk),GFP_KERNEL);
        if(!bb->ctx->cache_ops.opaque_data) {
	    	dprintk (KERN_WARNING "bb: cant allocate bb->ctx->cache_ops.opaque_data\n");
            /* XXX should probably change error code */
	    	goto out;
        }
        {
        struct bb_underdisk* d = 
            (struct bb_underdisk*)bb->ctx->cache_ops.opaque_data;
        d->bb=bb;
        d->bdev=bb->bdev_b;
        d->q=bb->bb_backing_queue_b;
        d->next_free_sector=0;
        d->log2_blocksize=bb->ctx->cache_ops.log2_blocksize;
	printk(KERN_WARNING "bb: cache log2_blocksize=%d\n",d->log2_blocksize);
        }
        if(!CACHE_init(bb->ctx,arg)) // XXX for now, default type, but this should be based on ioctl
        {
	    	dprintk (KERN_WARNING "bb: CACHE_init FAILED\n");
            /* XXX should probably change error code */
	    	goto out;
        }
#ifdef SIMPLE_LOCKS
        mutex_init(&bb->cache_lock);
#endif
#endif /* DISABLE_CACHE */
        return 0;
    }

	file = fget(arg);

	if (!file) {
		goto out;
	}

	inode = file->f_mapping->host;
	error = -EINVAL;

	dprintk (KERN_WARNING "bb: bb_set_fd fd %u inode %lu entered\n",
		arg, inode->i_ino);

	/* XXX Should we catch recursive BB device?
	 */

	if (!S_ISBLK(inode->i_mode)) {
		dprintk (KERN_WARNING "bb: file is not a block device\n");
		goto out_putf;
	}

	/* Switching backing store requires flushing existing request
	 * queue, but initial setup does not require this.
	 * See call to loop_switch in loop.c
	 */

	backing_dev = file->f_mapping->host->i_bdev;
	backing_queue = bdev_get_queue(backing_dev);

	if (!backing_queue) {
		dprintk (KERN_WARNING "bb: bad bb_backing_queue\n");
		goto out_putf;
	}

	if ((bb->backing_cnt++ % 2) == 0) {
		dprintk(KERN_WARNING "bb: set dev %p backing_queue_a %p\n",
		       backing_dev,
		       backing_queue);
		bb->bdev_a = backing_dev;
		bb->bb_backing_queue_a = backing_queue;
	}
	else {
		dprintk(KERN_WARNING "bb: set dev %p backing_queue_b %p\n",
		       backing_dev,
		       backing_queue);
		bb->bdev_b = backing_dev;
		bb->bb_backing_queue_b = backing_queue;
	}


	/* XXX Set the capacity based on the capacity of the backing
	 * disk based on sector size.
	 */

	if (bb->backing_cnt > 1) {
		blk_queue_hardsect_size(bb->bb_queue, bdev_hardsect_size(bb->bdev_a));
	#ifdef BB_FORCE_MAX_CAPACITY
		set_capacity(bb->bb_disk, 2*1024*BB_FORCE_MAX_CAPACITY);
	#else
		set_capacity(bb->bb_disk, 
        			get_capacity(bb->bdev_a->bd_disk));
	#endif

	}

	dprintk (KERN_WARNING "bb: bb_set_fd exited\n");
	
	return 0;

out_putf:
	fput(file);
out:
	return error;
}


static int __init bb_init(void)
{
	int i;

	dprintk (KERN_WARNING "bb: bb_init entered\n");

	/*
	 * Get registered.
	 */
	bb_major = register_blkdev(bb_major, "bb");
	if (bb_major <= 0) {
		dprintk(KERN_WARNING "bb: unable to get major number\n");
		return -EBUSY;
	}
	/*
	 * Allocate the device array, and initialize each one.
	 */
	Devices = kmalloc(ndevices * sizeof (struct bb_device *), GFP_KERNEL);
	if (Devices == NULL)
		goto out_unregister;
	for (i = 0; i < ndevices; i++) {
		Devices[i] = bb_alloc(i);

		if (Devices[i] == NULL) {
			dprintk (KERN_WARNING "bb: failed to allocate bb device\n");
			/* XXX */
		}

        Devices[i]->ctx = NULL; //default cache ctx is uninitialized
	}

	return 0;

  out_unregister:
	dprintk (KERN_WARNING "bb: failed to allocate bb devices\n");
	unregister_blkdev(bb_major, "bb");
	return -ENOMEM;

	return 0;
}

static void __exit bb_exit(void)
{
	int i;

	dprintk (KERN_WARNING "bb: bb_exit entered\n");

	for (i = 0; i < ndevices; i++) {
		struct bb_device *dev = Devices[i];
#ifndef DISABLE_CACHE
        if(dev && dev->ctx)
            CACHE_destroy(dev->ctx);
#endif
		bb_free(dev);
	}
	unregister_blkdev(bb_major, "bb");
	kfree(Devices);
}


static int bb_open(struct inode *inode, struct file *filp)
{
	struct bb_device *bb = inode->i_bdev->bd_disk->private_data;
	dprintk(KERN_WARNING "bb: bb_open entered\n");

#if 1
	if (!bb) {
		dprintk(KERN_WARNING "bb: bb_open failed\n");
		return 0;
	}
#endif
	dprintk(KERN_WARNING "bb: bb_open proceeding\n");

	/* XXX what does filp->private_data do?? 
	 * It is in sbull
	 */
	filp->private_data = bb;

	mutex_lock(&bb->bb_ctl_mutex);
	bb->bb_refcnt++;
	mutex_unlock(&bb->bb_ctl_mutex);

	return 0;
}


static int bb_release(struct inode *inode, struct file *file)
{
	struct bb_device *bb = inode->i_bdev->bd_disk->private_data;
	dprintk(KERN_WARNING "bb: bb_release entered\n");

#if 1
	if (!bb) {
		dprintk(KERN_WARNING "bb: bb_open failed\n");
		return 0;
	}
#endif
	dprintk(KERN_WARNING "bb: bb_release proceeding\n");

	mutex_lock(&bb->bb_ctl_mutex);
	--bb->bb_refcnt;
	mutex_unlock(&bb->bb_ctl_mutex);

	return 0;
}

static int bb_ioctl(struct inode * inode, struct file * file,
	unsigned int cmd, unsigned long arg)
{
	long size;
	struct hd_geometry geo;
	struct bb_device *bb = inode->i_bdev->bd_disk->private_data;
	int err;

	dprintk(KERN_WARNING "bb: bb_ioctl entered\n");

#if 1
	if (!bb) {
		dprintk(KERN_WARNING "bb: bb_ioctl failed\n");
		return 0;
	}
#endif

	mutex_lock(&bb->bb_ctl_mutex);
	switch (cmd) {
	case LOOP_SET_FD:
		err = bb_set_fd(bb, arg);
		break;
	case LOOP_CHANGE_FD:
		err = -EBADFD;
		/* XXX err = loop_change_fd(lo, file, inode->i_bdev, arg);*/
		break;
	case HDIO_GETGEO:
		dprintk(KERN_WARNING "bb: bb_ioctl HDIO_GETGEO\n");
		/* XXX hard-coded for sbull */
		size = nsectors * hardsect_size;
		size = size*(hardsect_size/KERNEL_SECTOR_SIZE);
		geo.cylinders = (size & ~0x3f) >> 6;
		geo.heads = 4;
		geo.sectors = 16;
		geo.start = 4;
		if (copy_to_user((void __user *) arg, &geo, sizeof(geo))) {
			err = -EFAULT;
		}
		else {
			err = 0;
		}
		break;
	default:
		dprintk(KERN_WARNING "bb: bb_ioctl unknown %x failed\n", cmd);
		err = -EINVAL;
	}
	mutex_unlock(&bb->bb_ctl_mutex);
	return err;
}

/* Handle a block I/O request. */
static int bb_make_request(struct request_queue *q, struct bio *bio)
{
	struct bb_device *bb = q->queuedata;
	int status = 0;

	dprintk(KERN_WARNING "bb: bb_make_request entered\n");

	status = bb_handle_bio(bb, bio);

	bio_endio(bio, bio->bi_size, status);

	dprintk(KERN_WARNING "bb: bb_make_request exited\n");

	return status;
}



static int bb_handle_bio(struct bb_device *bb, struct bio *bio)
{
	struct bb_underdisk args;
	BOOL rc;
	
	unsigned char *kaddr;
	unsigned int len;
	sector_t sector;
    void * obj;

	if ((bio->bi_rw & (1 << BIO_RW)) == 0) {
		/* Read */
#ifndef TRY_NO_DOUBLEBUFFER
		kaddr = bb->kbuf;
		len = bio->bi_size;

		if (len > bb->kbuf_len) {
			dprintk(KERN_WARNING "bb: bb_handle_bio bad len\n");
			return -EINVAL;
		}
        obj = kaddr;
#else
        obj = bio;
        len = bio->bi_size;
#endif /* TRY_NO_DOUBLE_BUFFER */
		sector = bio->bi_sector;

#ifndef DISABLE_CACHE
#ifdef SIMPLE_LOCKS
        mutex_lock(&bb->cache_lock);
#endif
		rc = CACHE_get(bb->ctx, ((ADDRESS)sector)<<9, obj, len);
#ifdef SIMPLE_LOCKS
        mutex_unlock(&bb->cache_lock);
#endif

		if(!rc) {
			dprintk(KERN_WARNING "bb: CACHE_get failed (%s)\n",
			       CACHE_ERROR2STR(bb->ctx->error));
			return -EINVAL; //different error?
		}
#else
		/* Fill struct args */
		args.bb = bb;
		args.bdev = bb->bdev_a;
		args.q = bb->bb_backing_queue_a;
        	args.log2_blocksize=mylog2(bdev_hardsect_size(bb->bdev_a));
		bb_sync_sector_read(&args, ((ADDRESS)sector)<<9, obj, len);
#endif

#ifndef TRY_NO_DOUBLEBUFFER
		/* Copy into bio buffer */
		copykern2bio(bio, kaddr, len);
	    	/* Wait for completion */
#endif
	}
	else {
		/* Write */
#ifndef TRY_NO_DOUBLEBUFFER
		kaddr = bb->kbuf;
		len = bio->bi_size;

		if (len > bb->kbuf_len) {
			dprintk(KERN_WARNING "bb: bb_handle_bio bad len\n");
			return -EINVAL;
		}

		copybio2kern(bio, kaddr, len);
        obj = kaddr;
#else
        obj = bio;
        len = bio->bi_size;
#endif /* TRY_NO_DOUBLEBUFFER */

		sector = bio->bi_sector;
#ifndef DISABLE_CACHE
#ifdef SIMPLE_LOCKS
        mutex_lock(&bb->cache_lock);
#endif
		rc = CACHE_put(bb->ctx, ((ADDRESS)sector)<<9, obj, len);
#ifdef SIMPLE_LOCKS
        mutex_unlock(&bb->cache_lock);
#endif
		if(!rc) {
			dprintk(KERN_WARNING "bb: CACHE_put failed (%s)\n",
			       CACHE_ERROR2STR(bb->ctx->error));
			return -EINVAL; //different error?
		}
#else
		/* Fill struct args */
		args.bb = bb;
		args.bdev = bb->bdev_a;
		args.q = bb->bb_backing_queue_a;
        	args.log2_blocksize=mylog2(bdev_hardsect_size(bb->bdev_a));
		bb_sync_sector_write(&args, ((ADDRESS)sector)<<9, obj, len);
#endif
		/* Wait for completion */
	}

	return 0;
}

static void copybio2kern(struct bio *bio, unsigned char* kaddr, unsigned int klen)
{
	struct bio_vec *bvec;
	int i;

    bio_for_each_segment(bvec, bio, i) {
        unsigned char *addr = __bio_kmap_atomic(bio, i, KM_USER0);
        unsigned int len=bvec->bv_len;
        if(klen < len) len=klen;
        memcpy(kaddr,addr,len);
        kaddr += len;
        klen -= len;
        __bio_kunmap_atomic(bio, KM_USER0);
        if(klen<=0) break;
    }
}

static void copykern2bio(struct bio *bio, unsigned char* kaddr, unsigned int klen)
{
	struct bio_vec *bvec;
	int i;

	bio_for_each_segment(bvec, bio, i) {
        unsigned char *addr = __bio_kmap_atomic(bio, i, KM_USER0);
        unsigned int len=bvec->bv_len;
        if(klen < len) len=klen;
        memcpy(addr,kaddr,len);
        kaddr += len;
        klen -= len;
		__bio_kunmap_atomic(bio, KM_USER0);
        if(klen<=0) break;
    }
}

static int bb_bio_readwritesync_end_io(struct bio *bio, unsigned int bytes, int status)
{
    struct bio_readwrite_args* args = (struct bio_readwrite_args*)bio->bi_private;
    int r=0;

    dprintk(KERN_WARNING "completing bb_bio_synchronous_readwrite\n");

    if(args->old_endio)
        r=args->old_endio(bio,bytes,status); //normal end_io function for map_kern
#ifdef TRY_NO_DOUBLEBUFFER
    bio_put(bio);
#endif
	if(args->c) complete(args->c);
    if(r) return r;

	return 0;
}
static int bb_bio_readwriteasync_end_io(struct bio *bio, unsigned int bytes, int status)
{
    struct completion* c = (struct completion*)bio->bi_private;

    dprintk(KERN_WARNING "completing bb_bio_asynchronous_readwrite\n");

#ifdef TRY_NO_DOUBLEBUFFER
    bio_put(bio);
#endif
	if(c) {
        complete(c);
    }

	return 0;
}
static int bb_bio_readwrite(
	struct bb_device *bb,     //needed???
	struct block_device* bdev, //destination blockdevice* needed???
	struct request_queue *q,  //destination request_queue*
	sector_t sector,          //sector to read/write
	unsigned char* buf,       //src/dst data (kernel mem)
	unsigned int bytes,       //buf size
	bool isWrite,              //true if writing to device
    struct completion* pc      //completion (NULL if synchronous)
	)
{
	struct bio *bio_dup;
	struct bio_readwrite_args args;
	unsigned int hss;
	DECLARE_COMPLETION_ONSTACK(c);  //completion for this request

	q = bdev_get_queue(bdev);

 	hss = bdev_hardsect_size(bdev);
	//printk(KERN_WARNING "bio readwrite hss=%u\n",hss);

    //printk(KERN_WARNING "bb_bio_synchronous_readwrite %p %p %p s:%08x buf:%p sz:%08x w?:%d hss:%d\n",bb,bdev,q,sector,buf,bytes,isWrite,hss);
    printk(KERN_WARNING "bb_bio_readwrite s:%08x\n",sector);
    printk(KERN_WARNING "bb_bio_readwrite buf:%p\n",buf);
    printk(KERN_WARNING "bb_bio_readwrite sz:%08x\n",bytes);
    printk(KERN_WARNING "bb_bio_readwrite w:%d\n",(int)isWrite);
    printk(KERN_WARNING "bb_bio_readwrite hss:%d\n",hss);
    printk(KERN_WARNING "bb_bio_readwrite pc:%p\n",pc);

	args.c=NULL;
	if(!pc)
		args.c=&c;

#ifndef TRY_NO_DOUBLEBUFFER
	bio_dup = bio_map_kern(q,buf,bytes,GFP_KERNEL); //is GFP_KERNEL ok?
	//blk_queue_bounce(q,&bio_dup); /* this didnt help */

    if(!bio_dup || bio_dup==ERR_PTR(-EINVAL) || IS_ERR(bio_dup)) {
        dprintk(KERN_WARNING "bio_map_kern FAILED!\n");
        return -1;
    }
    dprintk(KERN_WARNING "bio_map_kern success\n");

	args.old_endio = bio_dup->bi_end_io;
#else
    {
        /* buf is really the original bio YYY */
#if 0 /* bio_alloc didnt fix the async problem, but it may be part of a solution */
    struct bio* bio = (struct bio*)buf;
	bio_dup = bio_alloc(GFP_KERNEL, 1); //is 1 page correct???
    // is there a default endio? ... if not need to make one and bio_put

    if(!bio_dup || bio_dup==ERR_PTR(-EINVAL) || IS_ERR(bio_dup)) {
        dprintk(KERN_WARNING "bio_alloc  FAILED!\n");
        return -1;
    }
	bio_init(bio_dup);

	memcpy(bio_dup->bi_io_vec,
	       bio->bi_io_vec,
	       bio->bi_max_vecs * sizeof(struct bio_vec));

	bio_dup->bi_vcnt = bio->bi_vcnt;
	bio_dup->bi_size = bytes;
	bio_dup->bi_idx = bio->bi_idx;
#else
    bio_dup = bio_clone((struct bio*)buf,GFP_KERNEL);
    if(!bio_dup || bio_dup==ERR_PTR(-EINVAL) || IS_ERR(bio_dup)) {
        dprintk(KERN_WARNING "bio_clone  FAILED!\n");
        return -1;
    }
#endif
	args.old_endio = NULL;
	bio_phys_segments(q, bio_dup);
	bio_hw_segments(q, bio_dup);
    }
#endif

	bio_dup->bi_sector = sector; 
	bio_dup->bi_bdev = bdev; //needed?

	if(isWrite)
		/* Convert it into a write */
		bio_dup->bi_rw |= (1 << BIO_RW);
	else
		bio_dup->bi_rw &= ~(1 << BIO_RW);
        

    if(!pc)
    {
    	bio_dup->bi_end_io = bb_bio_readwritesync_end_io;
	    bio_dup->bi_private = &args; 
    }
    else
    {
	    bio_dup->bi_end_io = bb_bio_readwriteasync_end_io;
	    bio_dup->bi_private = pc; 
    }


	q->make_request_fn(
		q,
		bio_dup);

	//blkdev_issue_flush(bdev,NULL); //this wont complete here, but we dont care
	if(!pc) wait_for_completion(&c);


	return 0;
}

static int bb_bio_synchronous_readwrite(
	struct bb_device *bb,     //needed???
	struct block_device* bdev, //destination blockdevice* needed???
	struct request_queue *q,  //destination request_queue*
	sector_t sector,          //sector to read/write
	unsigned char* buf,       //src/dst data (kernel mem)
	unsigned int bytes,       //buf size
	bool isWrite              //true if writing to device
	)
{
    return bb_bio_readwrite(bb,bdev,q,sector,buf,bytes,isWrite,NULL);
}
static int bb_bio_asynchronous_readwrite(
	struct bb_device *bb,     //needed???
	struct block_device* bdev, //destination blockdevice* needed???
	struct request_queue *q,  //destination request_queue*
	sector_t sector,          //sector to read/write
	unsigned char* buf,       //src/dst data (kernel mem)
	unsigned int bytes,       //buf size
	bool isWrite,              //true if writing to device
    struct completion** pc    //expected that *pc=NULL
	)
{
    struct completion* c;
    if(!pc) return -1;
    c = (struct completion*)kzalloc(sizeof(struct completion),GFP_KERNEL);
    if(!c) return -1;
    *pc=c;
    init_completion(c);
    return bb_bio_readwrite(bb,bdev,q,sector,buf,bytes,isWrite,c);
}

static int bb_sync_sector_read(void *opaque, ADDRESS address, BYTE* data, size_t sz)
{
	int rc;
	struct bb_underdisk *args = opaque;

    printk(KERN_WARNING "bb_sync_sector_read %p %llx %p %08x %s\n",opaque,address,data,sz,args->bdev==args->bb->bdev_a?"PRIMARY":"CACHE");

	rc = bb_bio_synchronous_readwrite(
		args->bb,
		args->bdev,
		args->q,
		address>>9,
		data,
		sz,
		false /* isWrite */
		);

	return rc;
}

static int bb_sync_sector_write(void *opaque, ADDRESS address, BYTE* data, size_t sz)
{
	int rc;
	struct bb_underdisk *args = opaque;

    printk(KERN_WARNING "bb_sync_sector_write %p %llx %p %08x %s\n",opaque,address,data,sz,args->bdev==args->bb->bdev_a?"PRIMARY":"CACHE");

	rc = bb_bio_synchronous_readwrite(
		args->bb,
		args->bdev,
		args->q,
		address>>9,
		data,
		sz,
		true /* isWrite */
		);

	return rc;
}
static int bb_async_sector_write(void *opaque, ADDRESS address, BYTE* data, size_t sz, void** ppcompletion)
{
	int rc;
	struct bb_underdisk *args = opaque;

    printk(KERN_WARNING "bb_async_sector_write %p %llx %p %08x %s\n",opaque,address,data,sz,args->bdev==args->bb->bdev_a?"PRIMARY":"CACHE");

    if(ppcompletion) *ppcompletion=NULL;

#ifdef BB_FAKE_ASYNC
	rc = bb_bio_synchronous_readwrite(
		args->bb,
		args->bdev,
		args->q,
		address>>9,
		data,
		sz,
		true /* isWrite */
		);
#else
	rc = bb_bio_asynchronous_readwrite(
		args->bb,
		args->bdev,
		args->q,
		address>>9,
		data,
		sz,
		true, /* isWrite */
        (struct completion**)ppcompletion
		);
#endif
	return rc;
}
static int bb_async_sector_write_waitcomplete(void *opaque, ADDRESS address, BYTE* data, size_t sz, void* pcompletion)
{
#ifndef BB_FAKE_ASYNC
    wait_for_completion((struct completion*)pcompletion);
    kfree(pcompletion);
#endif
    return 0;
}

/*
 * Transfer a single BIO.
 */
static int bb_xfer_bio(struct bb_device *bb, struct bio *bio)
{
	struct request_queue *backing_queue;
	struct bio *bio_cpy;

	dprintk(KERN_WARNING "bb: bb_xfer_bio entered\n");

	if (!bb) {
		dprintk(KERN_WARNING "bb: bb_xfer_bio no device\n");
		return -EINVAL;
	}

	if (!bb->bb_backing_queue_a || !bb->bb_backing_queue_b) {
		dprintk(KERN_WARNING "bb: bb_xfer_bio no backing queue\n");
		return -EINVAL;
	}

	if (!bb->bb_backing_queue_a->make_request_fn
	    || !bb->bb_backing_queue_b->make_request_fn)
	{
		dprintk(KERN_WARNING "bb: bb_xfer_bio no backing queue fn\n");
		return -EINVAL;
	}

	bio_cpy = bio_clone(bio, GFP_NOIO);

	backing_queue = bb->bb_backing_queue_a;

	dprintk(KERN_WARNING "bb: xfr_io seq %d sector %ld len %d seg %d rw %lx\n",
	       bb->bb_bio_seq_cnt,
	       bio->bi_sector,
	       bio_sectors(bio),
	       bio_segments(bio),
	       bio->bi_rw
		);

	bio_cpy->bi_private = &bb->bb_bio_seq[bb->bb_bio_seq_cnt];

	if (++bb->bb_bio_seq_cnt == sizeof(bb->bb_bio_seq)
	    / sizeof(bb->bb_bio_seq[0]))
	{
		bb->bb_bio_seq_cnt = 0;
	}

	bio_cpy->bi_end_io = bb_bio_end_io;

	backing_queue->make_request_fn(
		backing_queue,
		bio_cpy);

	dprintk(KERN_WARNING "bb: bb_xfer_bio wait\n");

	if ((bio->bi_rw & (1 << BIO_RW)) == 0) {
		/* It's a read */
		wait_for_completion(&dup_write_complete);
	}

	dprintk(KERN_WARNING "bb: bb_xfer_bio exited\n");

	return 0;
}


static int bb_bio_end_io(struct bio *bio, unsigned int bytes, int status)
{
	struct bio *bio_dup;
	struct bb_seq_req *req = bio->bi_private;
	struct bb_device *bb = req->bb;
	int seq = req->seq;
	struct request_queue *q;

	dprintk(KERN_WARNING "bb: end_io seq %d sector %ld len %d seg %d\n",
	       seq,
	       bio->bi_sector,
	       bio_sectors(bio),
	       bio_segments(bio)
	);

	/* Create a new bio, fill and submit it to device b.
	 */

	if ((bio->bi_rw & (1 << BIO_RW))) {
		/* It's a write */
		return 0;
	}

	bio_dup = bio_alloc(GFP_KERNEL, 1);

	bio_init(bio_dup);

	q = bb->bb_backing_queue_b;

	memcpy(bio_dup->bi_io_vec,
	       bio->bi_io_vec,
	       bio->bi_max_vecs * sizeof(struct bio_vec));

	bio_dup->bi_sector = (bio->bi_sector - bytes / 512);
	bio_dup->bi_bdev = bb->bdev_b;

//	bio_dup->bi_flags |= 1 << BIO_CLONED;

	/* Convert it into a write */

	bio_dup->bi_rw = (1 << BIO_RW);

	bio_dup->bi_vcnt = bio->bi_vcnt;
	bio_dup->bi_size = bytes;
	bio_dup->bi_idx = bio->bi_idx;
	bio_phys_segments(q, bio);
	bio_hw_segments(q, bio);

	bio_dup->bi_end_io = bb_dup_bio_end_io;

	q->make_request_fn(
		q,
		bio_dup);

	return 0;
}

static int bb_dup_bio_end_io(struct bio *bio, unsigned int bytes, int status)
{
	int seq = 0;

	dprintk(KERN_WARNING "bb: dup_end_io seq %d sector %ld len %d seg %d\n",
	       seq,
	       bio->bi_sector,
	       bio_sectors(bio),
	       bio_segments(bio)
	);

	complete(&dup_write_complete);

	return 0;
}

module_init(bb_init);
module_exit(bb_exit);
