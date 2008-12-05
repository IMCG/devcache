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
//#include <linux/splice.h>

#include <linux/hdreg.h>	/* HDIO_GETGEO */


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
};

static struct bb_device **Devices = NULL;

/* Forward declarations */
static int bb_open(struct inode *inode, struct file *file);
static int bb_release(struct inode *inode, struct file *file);
static int bb_ioctl(struct inode * inode, struct file * file,
		    unsigned int cmd, unsigned long arg);

static int bb_make_request(struct request_queue *q, struct bio *bio);
static int bb_xfer_bio(struct bb_device*dev, struct bio *bio);


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

	bb->bb_queue = blk_alloc_queue(GFP_KERNEL);

	if (!bb->bb_queue)
		goto out_free_dev;

	blk_queue_make_request(bb->bb_queue, bb_make_request);

	/* XXX blk_queue_hardsect_size */
	blk_queue_hardsect_size(bb->bb_queue, hardsect_size);
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
	printk (KERN_WARNING "bb: bb_free entered\n");

	blk_cleanup_queue(bb->bb_queue);
	del_gendisk(bb->bb_disk);
	put_disk(bb->bb_disk);
	kfree(bb);

	printk (KERN_WARNING "bb: bb_free exited\n");
}

static int bb_set_fd(struct bb_device *bb,
		     struct file *bb_file, /* unused */
		     struct block_device *bdev,
		     unsigned int arg)
{
	int error;
	struct file *file;
	struct inode *inode;
	struct block_device *backing_dev;
	struct request_queue *backing_queue;

	printk (KERN_WARNING "bb: bb_set_fd entered\n");

	error = -EBADF;
	file = fget(arg);

	if (!file) {
		goto out;
	}

	inode = file->f_mapping->host;
	error = -EINVAL;

	/* XXX Catch recursive BB device.
	 */

	if (!S_ISBLK(inode->i_mode)) {
		goto out_putf;
	}

	/* Switching backing store requires flushing existing request
	 * queue, but initial setup does not require this.
	 * See call to loop_switch in loop.c
	 */

	backing_dev = file->f_mapping->host->i_bdev;
	backing_queue = bdev_get_queue(backing_dev);

	if (!backing_queue) {
		printk (KERN_WARNING "bb: bad bb_backing_queue\n");
		goto out_putf;
	}

	if ((bb->backing_cnt++ % 2) == 0) {
		printk (KERN_WARNING "bb: set backing_queue_a\n");
		bb->bdev_a = backing_dev;
		bb->bb_backing_queue_a = backing_queue;
	}
	else {
		printk (KERN_WARNING "bb: set backing_queue_b\n");
		bb->bdev_b = backing_dev;
		bb->bb_backing_queue_b = backing_queue;
	}


	/* XXX Set the capacity based on the capacity of the backing
	 * disk based on sector size.
	 */

	if (bb->backing_cnt > 1) {
		set_capacity(bb->bb_disk, 
			     2 * nsectors*(hardsect_size/KERNEL_SECTOR_SIZE));
	}

	printk (KERN_WARNING "bb: bb_set_fd exited\n");
	
	return 0;

out_putf:
	fput(file);
out:
	return error;
}


static int __init bb_init(void)
{
	int i;

	printk (KERN_WARNING "bb: bb_init entered\n");

	/*
	 * Get registered.
	 */
	bb_major = register_blkdev(bb_major, "bb");
	if (bb_major <= 0) {
		printk(KERN_WARNING "bb: unable to get major number\n");
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
			printk (KERN_WARNING "bb: failed to allocate bb device\n");
			/* XXX */
		}
	}
    
	return 0;

  out_unregister:
	printk (KERN_WARNING "bb: failed to allocate bb devices\n");
	unregister_blkdev(bb_major, "bb");
	return -ENOMEM;

	return 0;
}

static void __exit bb_exit(void)
{
	int i;

	printk (KERN_WARNING "bb: bb_exit entered\n");

	for (i = 0; i < ndevices; i++) {
		struct bb_device *dev = Devices[i];
		bb_free(dev);
	}
	unregister_blkdev(bb_major, "bb");
	kfree(Devices);
}


static int bb_open(struct inode *inode, struct file *filp)
{
	struct bb_device *bb = inode->i_bdev->bd_disk->private_data;
	printk(KERN_WARNING "bb: bb_open entered\n");

#if 1
	if (!bb) {
		printk(KERN_WARNING "bb: bb_open failed\n");
		return 0;
	}
#endif
	printk(KERN_WARNING "bb: bb_open proceeding\n");

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
	printk(KERN_WARNING "bb: bb_release entered\n");

#if 1
	if (!bb) {
		printk(KERN_WARNING "bb: bb_open failed\n");
		return 0;
	}
#endif
	printk(KERN_WARNING "bb: bb_release proceeding\n");

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

	printk(KERN_WARNING "bb: bb_ioctl entered\n");

#if 1
	if (!bb) {
		printk(KERN_WARNING "bb: bb_ioctl failed\n");
		return 0;
	}
#endif

	mutex_lock(&bb->bb_ctl_mutex);
	switch (cmd) {
	case LOOP_SET_FD:
		err = bb_set_fd(bb, file, inode->i_bdev, arg);
		break;
	case LOOP_CHANGE_FD:
		err = -EBADFD;
		/* XXX err = loop_change_fd(lo, file, inode->i_bdev, arg);*/
		break;
	case HDIO_GETGEO:
		printk(KERN_WARNING "bb: bb_ioctl HDIO_GETGEO\n");
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
		printk(KERN_WARNING "bb: bb_ioctl unknown %x failed\n", cmd);
		err = -EINVAL;
		/* XXX err = lo->ioctl ? lo->ioctl(lo, cmd, arg) : -EINVAL;*/
	}
	mutex_unlock(&bb->bb_ctl_mutex);
	return err;
}

/* Handle a block I/O request. */
static int bb_make_request(struct request_queue *q, struct bio *bio)
{
	struct bb_device *bb = q->queuedata;
	int status;

	printk(KERN_WARNING "bb: bb_make_request entered\n");

	status = bb_xfer_bio(bb, bio);

	bio_endio(bio, bio->bi_size, status);

	printk(KERN_WARNING "bb: bb_make_request exited\n");

	return 0;
}


/*
 * Transfer a single BIO.
 */
static int bb_xfer_bio(struct bb_device *bb, struct bio *bio)
{
	struct request_queue *backing_queue;
	struct bio *bio_cpy;

	printk(KERN_WARNING "bb: bb_xfer_bio entered\n");

	if (!bb) {
		printk(KERN_WARNING "bb: bb_xfer_bio no device\n");
		return -EINVAL;
	}

	if (!bb->bb_backing_queue_a || !bb->bb_backing_queue_b) {
		printk(KERN_WARNING "bb: bb_xfer_bio no backing queue\n");
		return -EINVAL;
	}

	if (!bb->bb_backing_queue_a->make_request_fn
	    || !bb->bb_backing_queue_b->make_request_fn)
	{
		printk(KERN_WARNING "bb: bb_xfer_bio no backing queue fn\n");
		return -EINVAL;
	}

	printk(KERN_WARNING "bb: bb_xfer_bio sector: %ld\n",
	       bio->bi_sector
		);

	bio_cpy = bio_clone(bio, GFP_NOIO);

	if (bio->bi_sector < nsectors ) {
		backing_queue = bb->bb_backing_queue_a;
	}
	else {
		bio_cpy->bi_sector -= nsectors;
		backing_queue = bb->bb_backing_queue_b;
	}

	backing_queue->make_request_fn(
		backing_queue,
		bio_cpy);

	printk(KERN_WARNING "bb: bb_xfer_bio exited\n");

	return 0;
}


module_init(bb_init);
module_exit(bb_exit);
