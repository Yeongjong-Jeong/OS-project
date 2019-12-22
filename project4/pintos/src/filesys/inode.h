#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"

struct bitmap;

/* Three types of data blocks. */
enum BLOCK_TYPE {DIRECT, SINGLE, DOUBLE};

/* Maximum allowable number of indices in indirect block. */
#define TOTAL_INDEX 128

/* Total number of direct blocks. */
#define NUM_DIRECT_BLOCKS 123
/* Maximum range of direct blocks. */
#define MAX_OFFSET_DIRECT (NUM_DIRECT_BLOCKS * BLOCK_SECTOR_SIZE)
/* Maximum range of single indirect blocks. */
#define MAX_OFFSET_SINGLE (MAX_OFFSET_DIRECT + TOTAL_INDEX*BLOCK_SECTOR_SIZE)
/* Maximum file size. */
#define MAX_FILE_SIZE 8388608  // 8MB = 8 * 1024 * 1024

/* Indirect data block. */
typedef struct _block_indirect_t
{
  block_sector_t block[TOTAL_INDEX];
} block_indirect_t;

/* Sector information.
   BLOCKTYPE indicate whether the data block can be accessed by
   directly, or single/double indirectly.
   In case of a direct data block, the data block can be accessed by 
   the index FIRST from the disk inode.
   In case of a single indirect data block, the data block can be accessed by
   the index FIRST from the indirect data block.
   In case of a double indiect data block, the data block can be accessed by
   the index FIST from the first indirect data block, and the index SECOND
   from the second indirect data block. */
typedef struct _block_sectors_t
{
  enum BLOCK_TYPE type;
  off_t first;   /* First sector to visit for accessing the data. */
  off_t second;  /* Second sector to visit. */
} block_sectors_t;

void inode_init (void);
bool inode_create (block_sector_t, off_t, bool);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
block_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);
void inode_refresh (struct inode *);
bool inode_is_dir (struct inode *);

#endif /* filesys/inode.h */
