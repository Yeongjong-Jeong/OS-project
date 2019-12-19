#include <hash.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/buffer-cache.h"
#include "userprog/syscall.h"
#include "threads/synch.h"
#include "threads/malloc.h"

/* Buffer head table. */
struct buffer_head *bh_table;

/* LRU Clock Algorithm. */
int lru_clock = 0;
struct lock lru_lock;

static void bt_init (void);
static void bt_destroy (void);
static struct buffer_head *bc_request (void);
static void bc_evict (struct buffer_head *bh);
static struct buffer_head *bc_choose_victim (void);
static void bh_setup (struct buffer_head *bh, bool new);


/* Allocate memory space for BUFFER_CACHE,
   and initialize the BUFFER_HEAD_TABLE to be pointing
   each buffer cache entry. */
void
bc_init (void)
{
  bh_table = malloc (sizeof (struct buffer_head) * NUM_BUFFER_CACHE);
  if (bh_table == NULL)
    exit (-1); // memory allocation failure error handle.

  /* Initialize the BUFFER_HEAD_TABLE. */
  bt_init ();

  /* Initialize LRU_LOCK. */
  lock_init (&lru_lock);
}

/* Initialize the BUFFER_HEAD_TABLE. */
static void
bt_init (void)
{
  int i = 0;
  for (i = 0; i < NUM_BUFFER_CACHE; i++)
    bh_setup (bh_table + i, true);
}

/* Free memory space of BUFFER_CACHE.
   Before freeing, flush all the dirty buffer cache into disk. */
void
bc_destroy (void)
{
  bc_flush_all ();
  bt_destroy ();
  free (bh_table);
}

static void
bt_destroy (void)
{
  int i = 0;
  for (i = 0; i < NUM_BUFFER_CACHE; i++)
    free(bh_table[i].cache);
}

/* Flush buffer cache associating with the given BUFFER HEAD.
   Call this function with BUFFER CACHE and associating lock acquired. */
void
bc_flush (struct buffer_head *bh)
{
  /* Flush the data in buffer cache to disk. */
  block_write (fs_device, bh->sector, bh->cache);

  /* LRU clock set. */
  bh->access = false;
  bh->dirty = false;
}

/* Flush all dirty buffer cache to the disk.
   This function should be called only when the file system shutdowns.*/
void
bc_flush_all (void)
{
  int i = 0;
  for (i = 0; i < NUM_BUFFER_CACHE; i++)
  {
    /* If the buffer cache is dirty, flush it to disk. */
    if (bh_table[i].dirty == true)
      bc_flush (bh_table + i);
    /* No need LRU clock setting. */
  }
}

/* Find buffer cache entry associating with the sector number SECTOR of disk.
   If exists, return the pointer to BUFFER_HEAD.
   Otherwise, return NULL. */
struct buffer_head *
bc_find_bh (block_sector_t sector)
{
  int i;
  for (i = 0; i < NUM_BUFFER_CACHE; i++)
  {
    lock_acquire (&bh_table[i].lock);

    /* Return the BUFFER HEAD with lock acquired. */
    if (bh_table[i].sector == sector)
      return &bh_table[i];

    lock_release (&bh_table[i].lock);
  }
  return NULL;
}

/* Return the empty buffer cache with lock acquired. */
static struct buffer_head *
bc_request (void)
{
  int i = 0;
  struct buffer_head *cur = NULL;

  /* Scan the BUFFER CACHE TABLE, and return the empty buffer cache. */
  for (i = 0; i < NUM_BUFFER_CACHE; i++)
  {
    cur = bh_table + i;
    lock_acquire (&cur->lock);
    
    /* If the buffer cache is empty,
       return the empty buffer cache with lock acquired. */
    if (cur->in_use == false)
      return cur;

    lock_release (&cur->lock);
  }

  /* There's no empty buffer cache, so need to evict some. */
  cur = bc_choose_victim ();
  /* bc_choose_victim () returns the victim with lock acquired. */
  bc_evict (cur);

  /* Return the empty buffer cache just evicted with associating lock. */
  return cur;
}

static void
bc_evict (struct buffer_head *bh)
{
  /* The lock associating with the INPUT buffer cache
     is already acquired by bc_choose_victim (). */

  /* Check whether the buffer cache is dirty or not. */
  /* If dirty, FLUSH the data in the buffer cache to disk. */
  if (bh->dirty == true)
    bc_flush (bh);
  bh->in_use = false;
}

/* Choose a buffer cache entry to be evicted
   when there's no more empty space for cache.
   NOTICE - The empty buffer cache is returned with lock acquired. */
static struct buffer_head *
bc_choose_victim (void)
{
  struct buffer_head *cur = NULL;

  /* Clock algorithm. */
  lock_acquire (&lru_lock);
  while (1)
  {
    cur = bh_table + lru_clock;
    
    lock_acquire (&cur->lock);
    if (cur->access == true)
    {
      cur->access = false;
      lock_release (&cur->lock);
      lru_clock = (lru_clock + 1) % NUM_BUFFER_CACHE;
    }
    else
      break;
  }
  lock_release (&lru_lock);

  /* Return the victim with associating lock acquired. */
  return cur;
}

/* Read the data from the buffer cache. */
void
bc_read (void *buffer_, off_t bytes_read, block_sector_t sector_idx,
         int sector_ofs, int chunk_size)
{
  /* Search for the buffer cache associating with SECTOR_IDX. */
  struct buffer_head *bh = bc_find_bh (sector_idx);
  uint8_t *bc = NULL;
  uint8_t *buffer = buffer_;

  /* bc_find_bh returns the BH with lock acquired if BH is not NULL. */
  
  /* If there's no buffer cache,
     cache the data which will be read from disk. */
  if (bh == NULL)
  {
    /* Get a space for buffer cache. */
    bh = bc_request();

    /* BUFFER_HEAD should be allocated. */
    ASSERT (bh != NULL);

    /* Cache: Read data from the disk to the buffer cache. */
    block_read (fs_device, sector_idx, bh->cache);
    bh->sector = sector_idx;
    bh->in_use = true;
  }

  /* Pass the data from the buffer cache to the user BUFFER. */
  bc = bh->cache;
  memcpy (buffer + bytes_read, bc + sector_ofs, chunk_size);

  /* LRU clock set. */
  bh->access = true;
  lock_release (&bh->lock);
}

/* Write the data to the buffer cache. */
void
bc_write (void *buffer_, off_t bytes_written, block_sector_t sector_idx, 
          int sector_ofs, int chunk_size)
{
  /* Search for the buffer cache associating with SECTOR_IDX. */
  struct buffer_head *bh = bc_find_bh (sector_idx);
  uint8_t *bc = NULL;
  uint8_t *buffer = buffer_;

  /* bc_find_bh returns the BH with lock acquired if BH is not NULL. */
  
  /* If there's no buffer cache,
     cache the data which will be written to disk. */
  if (bh == NULL)
  {
    /* Get a space for buffer cache.
       bh_request returns the BH with lock acquired. */
    bh = bc_request();

    /* BUFFER_HEAD should be allocated. */
    ASSERT (bh != NULL);

    /* Cache: Read data from the disk to the buffer cache. */
    block_read (fs_device, sector_idx, bh->cache);
    bh->sector = sector_idx;
    bh->in_use = true;
  }

  /* Write the data from the user BUFFER to buffer cache. */
  bc = bh->cache;
  memcpy (bc + sector_ofs, buffer + bytes_written, chunk_size);

  /* LRU clock set. */
  bh->access = true;
  bh->dirty = true;
  lock_release (&bh->lock); // Release the lock.
}

/* NEW is 1 -> new initialize, NEW is 0 -> just reset. */
static void
bh_setup (struct buffer_head *bh, bool new)
{
  bh->in_use = false;
  bh->dirty = false;
  bh->access = false;
  bh->inode = NULL;
  if (new)
  {
    bh->cache = malloc (BLOCK_SECTOR_SIZE);
    if (bh->cache == NULL)
      exit (-1);
    lock_init (&bh->lock);
  }
}

