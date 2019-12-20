#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/buffer-cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    block_sector_t direct[NUM_DIRECT_BLOCKS]; /* Direct blocks. */
    block_sector_t single_indirect;     /* Indirect block. */
    block_sector_t double_indirect;     /* Double indirect block. */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Copy of associating disk inode. */
    struct lock lock;                   /* Lock to modify on-disk inode. */
  };

static block_sector_t byte_to_sector (struct inode *inode, off_t pos);
static bool inode_update_disk_inode (struct inode_disk *inode_disk,
                                     block_sectors_t *sectors,
                                     block_sector_t newest);
static void inode_free_data_all (struct inode *inode);
static struct inode_disk *inode_to_disk_inode (struct inode *inode);
static bool inode_get_index (off_t pos, block_sectors_t *sectors);
static bool inode_append (struct inode_disk *inode_disk, off_t start, off_t length);



/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (struct inode *inode, off_t pos)
{
  block_sectors_t sectors;
  struct inode_disk *inode_disk = inode_to_disk_inode (inode);

  ASSERT (inode_disk != NULL);

  /* Byte offset POS should be smaller than the file length. */
  if (pos < inode_disk->length)
  {
    /* Invalid byte offset POS. */
    if (!inode_get_index (pos, &sectors))
      return -1;

    /* If byte offset is in direct block, */
    if (sectors.type == DIRECT)
      return inode_disk->direct[sectors.first];
    /* If byte offset is in single indirect block, */
    else if (sectors.type == SINGLE)
    {
      block_indirect_t *indirect_block = malloc (sizeof (block_indirect_t));
      if (indirect_block == NULL)
        return -1;
      
      /* Access to the first indirect data block. */
      bc_read (indirect_block->block, 0, inode_disk->single_indirect, 0,
               BLOCK_SECTOR_SIZE);
      block_sector_t sector_idx = indirect_block->block[sectors.first];
      
      free (indirect_block);
      return sector_idx;
    }
    /* If byte offset is in double indirect block, */
    else
    {
      block_indirect_t *indirect_block = malloc (sizeof (block_indirect_t));
      if (indirect_block == NULL)
        return -1;

      /* Access to the first indirect data block. */
      bc_read (indirect_block->block, 0, inode_disk->double_indirect, 0,
               BLOCK_SECTOR_SIZE);
      block_sector_t sector_idx = indirect_block->block[sectors.first];
      
      /* Access to the second indirect data block. */
      bc_read (indirect_block->block, 0, sector_idx, 0, BLOCK_SECTOR_SIZE);
      sector_idx = indirect_block->block[sectors.second];
      
      free (indirect_block);
      return sector_idx;
    }  // sectors.type == DOUBLE
  }
  else
  {
    printf ("Exceeds size\n");
    printf ("size is %d\n", inode_disk->length);
    return -1;
  }
}





/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  printf ("inode_create ()\n");

  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      
      if (length > 0)
        inode_append (disk_inode, 0, length);
      
      bc_write (disk_inode, 0, sector, 0, BLOCK_SECTOR_SIZE);

      printf ("inode_create () : length = %d\n", disk_inode->length);
      bc_read (disk_inode, 0, sector, 0, BLOCK_SECTOR_SIZE);
      printf ("inode_create () : length = %d\n", disk_inode->length);


      free (disk_inode);
      success = true;
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  printf ("inode_open ()\n");

  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;

  printf ("inode_open () : sector : %d\n", sector);

  inode_to_disk_inode (inode);

  printf ("inode_open () : length : %d\n", inode->data.length);

  lock_init (&inode->lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  printf ("inode_close () : sector : %d\n", inode->sector);

  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          inode_free_data_all (inode);
          struct buffer_head *bh = bc_find_bh (inode->sector);
          if (bh != NULL)
      	    bc_flush (bh);
          free_map_release (inode->sector, 1); 
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  printf ("inode_read_at ()\n");
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);

      if (sector_idx == -1)
        break;

      printf ("read: sector : %d, offset : %d, size : %d\n", sector_idx, offset, size);

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      bc_read (buffer, bytes_read, sector_idx, sector_ofs, chunk_size);

            
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  printf ("inode_write_at ()\n");
  printf ("write at : %d with size %d\n", offset, size);

  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  struct inode_disk *inode_disk = inode_to_disk_inode (inode);
  if (inode_disk == NULL)
    return 0;

  lock_acquire (&inode->lock);
  /* If the write access try to extend the file size,
     append the data block into DISK_INODE. */
  if (offset + size > inode_disk->length)
  {
    printf ("*********inode_write_at (): append ()**********\n");
    inode_append (inode_disk, offset, size);
    inode_disk->length = (offset + size);
    bc_write (inode_disk, 0, inode->sector, 0, BLOCK_SECTOR_SIZE);
    inode_to_disk_inode (inode); // Update in-memory inode.
  }
  lock_release (&inode->lock);

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      bc_write ((void *)buffer, bytes_written, sector_idx,
		sector_ofs, chunk_size);

      printf ("write: sector : %d\n", sector_idx);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

/* Update the disk inode information for newly appended data sector. */
static bool
inode_update_disk_inode (struct inode_disk *inode_disk,
                         block_sectors_t *sectors, block_sector_t newest)
{
  printf ("inode_update_disk_inode ()\n");

  /* Sector number of a indirect block. */
  block_sector_t sector;

  /* If the newly appended data is directly accessible, */
  if (sectors->type == DIRECT)
  {
    inode_disk->direct[sectors->first] = newest;
  }
  /* If the newly appended data is single-indirect data block, */
  else if (sectors->type == SINGLE)
  {
    block_sector_t *indirect_block = calloc (TOTAL_INDEX,
                                             sizeof (block_sector_t));
    if (indirect_block == NULL)
      return false;
    
    /* Indirect block is not yet allocated. */
    if (sectors->first == 0)
    {
      /* Allocate the indirect block. */
      if (!free_map_allocate (1, &sector))
        return false;
      inode_disk->single_indirect = sector;
      /* No need to read, just write directly. */
    }
    else /* Indirect block is already allocated, so just read. */
    {
       /* Read the indirect block. */
      bc_read (indirect_block, 0, inode_disk->single_indirect, 0,
              BLOCK_SECTOR_SIZE);
    }

    /* Update the indirect block. */
    indirect_block[sectors->first] = newest;
    
    /* Write the sector information which can directly access
       to data block in single indirect block. */
    bc_write (indirect_block, 0, inode_disk->single_indirect, 0,
              BLOCK_SECTOR_SIZE);
    
    free (indirect_block);
  }
  else // double indirect data block.
  {
    block_sector_t *indirect_block1 = calloc (TOTAL_INDEX,
                                              sizeof (block_sector_t));
    if (indirect_block1 == NULL)
      return false;
    block_sector_t *indirect_block2 = calloc (TOTAL_INDEX,
                                              sizeof (block_sector_t));
    if (indirect_block2 == NULL)
    {
      free (indirect_block1);
      return false;
    }

    /* Update the first indirect block. */
    /* First indirect block is not yet allocated. */
    if (sectors->first == 0 && sectors->second == 0)
    {
      /* Allocate the first indirect block. */
      if (!free_map_allocate (1, &sector))
        return false;
      inode_disk->double_indirect = sector;
      /* No need to read, just write directly. */
    }
    else /* First indirect block is already allocated, so just read. */
    {
       /* Read the first indirect block. */
      bc_read (indirect_block1, 0, inode_disk->double_indirect, 0,
               BLOCK_SECTOR_SIZE);
    }

    /* Second indirect block is not yet allocated. */
    if (sectors->second == 0)
    {
      /* Allocate the indirect block. */
      if (!free_map_allocate (1, &sector))
        return false;

      /* Update the first indirect block. */
      indirect_block1[sectors->first] = sector;
      bc_write (indirect_block1, 0, inode_disk->double_indirect, 0,
                BLOCK_SECTOR_SIZE);
    }
    else /* Indirect block is already allocated, so just read. */
    {
       /* Read the indirect block. */
      bc_read (indirect_block2, 0, indirect_block1[sectors->first], 0,
               BLOCK_SECTOR_SIZE);
    }

    /* Update the second indirect block. */
    indirect_block2[sectors->second] = newest;
    bc_write (indirect_block2, 0, indirect_block1[sectors->first], 0,
              BLOCK_SECTOR_SIZE);

    free (indirect_block1);
    free (indirect_block2);
  }

  return true;
}

static void
inode_free_data_all (struct inode *inode)
{
  struct inode_disk * inode_disk = inode_to_disk_inode (inode);
  int i, j;
  block_indirect_t *indirect_block1 = malloc (sizeof (block_indirect_t));
  if (indirect_block1 == NULL)
    return ;
  block_indirect_t *indirect_block2 = malloc (sizeof (block_indirect_t));
  if (indirect_block2 == NULL)
  {
    free (indirect_block1);
    return ;
  }

  /* Free the resource of direct blocks - only data blocks. */
  for (i = 0; i < NUM_DIRECT_BLOCKS; i++)
  {
    if (inode_disk->direct[i] > 0)
    {
      struct buffer_head *bh = bc_find_bh (inode_disk->direct[i]);
      if (bh != NULL)
      	bc_flush (bh);
      free_map_release (inode_disk->direct[i], 1);
    }
    else
      break;
  }

  /* Free the resource of single indirect block - data blocks
     and the associating indirect block. */
  if (inode_disk->single_indirect > 0)
  {
    bc_read (indirect_block1->block, 0, inode_disk->single_indirect, 0,
             BLOCK_SECTOR_SIZE);
    for (i = 0; i < TOTAL_INDEX; i++)
    {
      if (indirect_block1->block[i] > 0)
        free_map_release (indirect_block1->block[i], 1);
      else
        break;
    }
  }

  /* Free the resource of double indirect block - data blocks
     ,the associating first indirect block
     and the following second indirect blocks.*/
  if (inode_disk->double_indirect > 0)
  {
    bc_read (indirect_block1->block, 0, inode_disk->double_indirect, 0,
             BLOCK_SECTOR_SIZE);
    for (i = 0; i < TOTAL_INDEX; i++)
    {
      if (indirect_block1->block[i] > 0)
      {
        bc_read (indirect_block2->block, 0, indirect_block1->block[i], 0,
                 BLOCK_SECTOR_SIZE);
        for (j = 0; j < TOTAL_INDEX; j++)
        {
          if (indirect_block2->block[j] > 0)
            free_map_release (indirect_block2->block[j], 1);
          else
            break;
        }
        free_map_release (indirect_block1->block[i], 1);
      }
      else
        break;
    }
  }

  free (indirect_block1);
  free (indirect_block2);
}

/* Update the member variable of in-memory inode DATA
   which contains a copy of the associating disk inode.
   Return the pointer to the disk inode.
   You should free the pointer. */
static struct inode_disk *
inode_to_disk_inode (struct inode *inode)
{
  bc_read (&inode->data, 0, inode->sector, 0, BLOCK_SECTOR_SIZE);
  
  return &inode->data;
}

/* Receive the byte offset POS and the pointer to data block index container.
   This function fill in the contents on data block index container.
   Return TRUE if the POS is valid, return FALSE otherwise. */
static bool
inode_get_index (off_t pos, block_sectors_t *sectors)
{
  /* Invalid access. POS exceeds maximum allowable file length. */
  if (pos >= MAX_FILE_SIZE)
    return false;

  if (pos < MAX_OFFSET_DIRECT)
  {
    sectors->first = pos / BLOCK_SECTOR_SIZE;
    sectors->second = -1;
    sectors->type = DIRECT;
  }
  else if (pos < MAX_OFFSET_SINGLE)
  {
    sectors->first = (pos - MAX_OFFSET_DIRECT) / BLOCK_SECTOR_SIZE;
    sectors->second = -1;
    sectors->type = SINGLE;
  }
  else
  {
    off_t capacity = (BLOCK_SECTOR_SIZE * BLOCK_SECTOR_SIZE);
    off_t start = (pos - MAX_OFFSET_SINGLE);
    sectors->first = start / capacity;
    sectors->second = (start % capacity) / BLOCK_SECTOR_SIZE;
    sectors->type = DOUBLE;
  }

  return true;
}

/*  */
static bool
inode_append (struct inode_disk *inode_disk, off_t start, off_t length)
{
  printf ("inode_append ()\n");

  int sector_ofs, chunk_size;   /* Offset in a disk sector. */
  block_sector_t sector;
  char *zeros = (char *) calloc (1, BLOCK_SECTOR_SIZE);
  block_sectors_t sectors;

  while (length > 0)
  {
    sector_ofs = start % BLOCK_SECTOR_SIZE;

    /* Allocate a sector only when there's no associating sector. */
    if (sector_ofs == 0)
    {
      if (free_map_allocate (1, &sector))
      {
        /* Get indices corresponding to the newly appended file position. */
        if (!inode_get_index (start, &sectors))
        {
          free (zeros);
          return false;
        }

        /* Update the disk inode. */
        inode_update_disk_inode (inode_disk, &sectors, sector);

	printf ("sector: %d\n", sector);
	printf ("type : %d\n", sectors.type);
	printf ("first : %d\n", sectors.first);
	printf ("second : %d\n", sectors.second);

        bc_write (zeros, 0, sector, 0, BLOCK_SECTOR_SIZE);
      }
      else
      {
        free (zeros);
        return false;
      }
    }
    else
    {
      printf ("inode_append (): already exist\n");
    }

    start += (BLOCK_SECTOR_SIZE - sector_ofs);
    length -= (BLOCK_SECTOR_SIZE - sector_ofs);
  }

  free (zeros);
  return true;
}
