#ifndef FILESYS_BUFFER_CACHE_H
#define FILESYS_BUFFER_CACHE_H

#include "devices/block.h"
#include "threads/synch.h"
#include "filesys/off_t.h"

#define NUM_BUFFER_CACHE 64           /* Number of buffer cache entries. */

/* Metadata for a buffer cache entry. */
struct buffer_head
  {
    void *cache;            /* VADDR of the associated buffer cache entry. */
    block_sector_t sector;  /* On-disk location. */
    bool in_use;            /* In-use flag. */
    bool access;            /* Recently-accessed flag. LRU Clock. */
    bool dirty;             /* Dirty flag. */
    struct inode *inode;
    struct lock lock;       /* Lock. */
  };


/* Functions - Buffer cache. */
void bc_init ();
void bc_destroy (void);
void bc_flush (struct buffer_head *bh);
void bc_flush_all (void); /* need? */
struct buffer_head *bc_find_bh (block_sector_t sector);
void bc_read (void *buffer, off_t bytes_read, block_sector_t sector_idx,
		int sector_ofs, int chunk_size);
void bc_write (void *buffer, off_t bytes_written, block_sector_t sector_idx,
		int sector_ofs, int chunk_size);

#endif
