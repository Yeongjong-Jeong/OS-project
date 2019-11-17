#ifdef USERPROG

#include "vm/page.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include "devices/block.h"
#include "userprog/pagedir.h"
#include <string.h>
// #include <debug.h>
// #include <stddef.h>
// #include <stdio.h>

/************************* Demanding page related *************************/
static hash_hash_func vm_hash_func;
static hash_less_func vm_less_func;
static hash_action_func vm_destroy_func;

/* Initialize the hash table storing VM_ENTRYs. */
void
vm_init (struct hash* vm)
{
  hash_init (vm, vm_hash_func, vm_less_func, NULL);
}

/* Delete the hash table. */
void
vm_destroy (struct hash* vm)
{
  hash_destroy (vm, vm_destroy_func);
}

/* Search vm_entry corresponding to VADDR
   in the address space of the current process.
   Return VM_ENTRY if exists, return NULL otherwise. */
struct vm_entry*
find_vme (void *vaddr)
{
  struct hash *vm = &thread_current ()->vm;
  struct vm_entry vme;
  struct hash_elem *elem;
  
  vme.vaddr = pg_round_down (vaddr);
  elem = hash_find (vm, &vme.elem);
  
  if (elem != NULL)
    return hash_entry (elem, struct vm_entry, elem);
  else
    return NULL;
}

/* Insert VM_ENTRY to hash table.
   Return TRUE if successful, return FALSE otherwise. */
bool
insert_vme (struct hash *vm, struct vm_entry *vme)
{
  if (hash_insert (vm, &vme->elem) == NULL)
    return true;
  else
    return false;
}

/* Delete VM_ENTRY from hash table.
   Return TRUE if successful, return FALSE otherwise. */
bool
delete_vme (struct hash *vm, struct vm_entry *vme)
{
  if (hash_delete (vm, &vme->elem) == NULL)
    return false;
  else
    return true;
}

/* Calculate the bucket number of the hash table for the VM_ENTRY.
   Use hashed value of the virtual page number as a bucket number. */
static unsigned
vm_hash_func (const struct hash_elem *e, void *aux)
{
  struct vm_entry *vme = hash_entry (e, struct vm_entry, elem);
  return hash_int ((int) pg_round_down (vme->vaddr));
}

/* Compare address values of two entered hash_elem.
   Return TRUE if address value of A is smaller than that of b,
   return FALSE otherwise. */
static bool
vm_less_func (const struct hash_elem *a,
              const struct hash_elem *b,
              void *aux)
{
  struct vm_entry *avme = hash_entry (a, struct vm_entry, elem);
  struct vm_entry *bvme = hash_entry (b, struct vm_entry, elem);

  if (avme->vaddr < bvme->vaddr)
    return true;
  else
    return false;
}

/* Remove memory of VM_ENTRY. */
static void
vm_destroy_func (struct hash_elem *e, void *aux UNUSED)
{
  struct vm_entry *vme = hash_entry (e, struct vm_entry, elem);
  free ((void *) vme);
}

void
setup_vm_entry (struct vm_entry *e, uint8_t type, bool writable,
                bool in_memory, void *uvaddr, struct file* file,
                off_t offset, size_t read_bytes, size_t zero_bytes)
{
  e->type = type;
  e->writable = writable;
  e->in_memory = in_memory;
	e->pin_flag = false;
  e->vaddr = uvaddr;
  e->file = file;
  e->offset = offset;
  e->read_bytes = read_bytes;
  e->zero_bytes = zero_bytes;
	e->swap_index = 0;
}

/* Load the file page from the disk to physical memory. */
bool
load_file (void *kaddr, struct vm_entry *vme)
{
  /* Locate the offset of the file to be loaded. */
  file_seek (vme->file, vme->offset);

  // Implement function to load a page to kaddr by <file, offset> of vme.
  if (file_read (vme->file, kaddr, vme->read_bytes)
      != (int) vme->read_bytes)
    return false;
  
  // Pad 0 as much as zero_bytes.
  memset (kaddr + vme->read_bytes, 0, vme->zero_bytes);
  
  // File is successfully loaded, return true.
  return true;
}

/****************************** SWAP related ******************************/
static void _setup_page (struct page* page, void *kpage);
static void page_page_free (struct page* page);
static size_t swap_find_empty_slot_and_flip (void);
static void swap_reset_bitmap (size_t slot_index);

/* Initialize the global variable LRU_LIST */
void
lru_init (void)
{
  list_init (&lru_list);   /* Initialize LRU_LIST. */
  lock_init (&lru_lock);   /* Initialize LRU_LOCK. */
}

/* Allocate a page and return PAGE structure associating with the page.
   If the memory lacks, evict some pages to respond to this function call. */
struct page *
page_alloc (enum palloc_flags flags)
{
  void *kaddr;
  struct page *page;

	lock_acquire (&lru_lock);
  /* Try to get a page from the USER POOL. */
  while (! (kaddr = palloc_get_page (flags)))
  {
		lock_release (&lru_lock);
    swap_choose_victim_and_free_page ();
  }
	lock_release (&lru_lock);

  /* Create PAGE entry. */
  page = (struct page*) malloc (sizeof (struct page));
  /* Set up the members of the PAGE entry. */
  _setup_page (page, kaddr);

  /* Insert the PAGE structure to LRU_LIST. */
  page_insert_to_lru_list (page);
	
  return page;
}

void
page_free (void *kaddr)
{
  bool find = false;
  struct page *page;
  struct list_elem *e;

	lock_acquire (&lru_lock);
  /* Find the PAGE entry whose KADDR is same
     with the input KADDR in the LRU_LIST. */
  for (e = list_begin (&lru_list); e != list_end (&lru_list);
       e = list_next (e))
  {
    page = list_entry (e, struct page, elem);
    if (page->kaddr == kaddr)
    {
      find = true;
      break;
    }
  }

  if (!find)
    return ;

  page_page_free (page);
	lock_release (&lru_lock);
}

void
page_insert_to_lru_list (struct page* page)
{
  list_push_back (&lru_list, &page->elem);
}

void
page_remove_from_lru_list (struct page* page)
{
  list_remove (&page->elem);
}

void
swap_init (void)
{
  size_t bitmap_size; /* block_sector_t == uint32_t */

  /* Create a block for swap. */
  swap_block = block_get_role (BLOCK_SWAP);
  if (swap_block == NULL)
    return; // do something.

  /* The number of pages in a SWAP_BLOCK == SWAP_BITMAP size. */
  bitmap_size = block_size (swap_block) / SECTORS_PER_PAGE;

  /* Create a bitmap for maintaining the swap partition.
     Each swap partition is managed per 4KBytes swap slot. */
  swap_bitmap = bitmap_create (bitmap_size);
  if (swap_bitmap == NULL)
    return ; // do something.

  /* Set all entry in the bitmap to 0. */
  bitmap_set_all (swap_bitmap, false);
  
  /* Initialize SWAP_LOCK. */
  lock_init (&swap_lock);
}

/* Choose a victim from LRU_LIST, swap the page out if needed.
   And then free the page. */
void
swap_choose_victim_and_free_page (void)
{
  /* FIFO: Just choose the first page in the LRU_LIST. */
  struct list_elem *e = list_begin (&lru_list);
	e = list_next (e);
	e = list_next (e);
	e = list_next (e);
	e = list_next (e);

  struct page *page = list_entry (e, struct page, elem);
  size_t index_to_swap = 0;

  switch (page->vme->type)
  {
    /* VM_BIN.
       If dirty bit is 1, write to the swap partition and free the page frame.
       And then, change type to VM_ANON for demanding paging. */
    case VM_BIN:
    {
      if (pagedir_is_dirty (page->thread->pagedir, page->vme->vaddr))
      {
        index_to_swap = swap_write_to_disk (page->kaddr);
        page->vme->swap_index = index_to_swap;
        page->vme->type = VM_ANON;
      }
      break;
    }
    /* VM_FILE.
       If dirty bit is 1, write to the to the file and free the page frame. 
       If dirty bit is 0, just free the page frame. */
    case VM_FILE:
    {
      if (pagedir_is_dirty (page->thread->pagedir, page->vme->vaddr))
      {
        lock_acquire (&filesys_lock);
        file_write_at (page->vme->file, page->vme->vaddr,
                       PGSIZE, page->vme->offset);
        lock_release (&filesys_lock);
      }
      break;
    }
    /* VM_ANON.
       Write to the swap partition. */
    case VM_ANON:
    {
      index_to_swap = swap_write_to_disk (page->kaddr);
      page->vme->swap_index = index_to_swap;
      break;
    }
  }
  
  page->vme->in_memory = false;
 
  /* Mark page "not present" in page directory. */
  pagedir_clear_page (page->thread->pagedir, page->vme->vaddr);

	/* Free the page frame. */
  page_page_free (page);
 
	lock_acquire (&lru_lock);
}

void
set_pin (void)
{
	struct hash *vm = &thread_current ()->vm;
	struct hash_iterator i;
	struct hash_elem *e;
	struct vm_entry *vme;

	hash_first (&i, vm);
	while (e = hash_next (&i))
	{
		vme = hash_entry (e, struct vm_entry, elem);
		vme->pin_flag = true;
	}
}

void
reset_pin (void)
{
	struct hash *vm = &thread_current ()->vm;
	struct hash_iterator i;
	struct hash_elem *e;
	struct vm_entry *vme;

	hash_first (&i, vm);
	while (e = hash_next (&i))
	{
		vme = hash_entry (e, struct vm_entry, elem);
		vme->pin_flag = false;
	}
}

size_t
swap_write_to_disk (void *kaddr)
{
	size_t i = 0;
  size_t index_to_swap = 0;
  block_sector_t sector;

  /* Find a first-fit location in SWAP_SPACE.
     This process should be implemented atomically,
     because the other process should not choose the same sector. */
  lock_acquire (&swap_lock);
  index_to_swap = swap_find_empty_slot_and_flip ();

  /* No more space to write, error occurs. */
  if (index_to_swap == BITMAP_ERROR)
    exit (-1);

	sector = index_to_swap * SECTORS_PER_PAGE;

  for (i = 0; i < SECTORS_PER_PAGE; i++)
  {
    block_write (swap_block, sector + i,
                 (void *)((char *)kaddr + i * BLOCK_SECTOR_SIZE));
  }
  lock_release (&swap_lock);

  return index_to_swap;
}

void
swap_read_from_disk (size_t slot_index, void *kaddr)
{
	int i = 0;
  block_sector_t sector = slot_index * SECTORS_PER_PAGE;

  /* ASSERT () : whether the slock_index is in used or not.
     If the slot_index is not in used, ERROR occurs. */

  /* block_read (struct block *block, block_sector_t sector, void *buffer) */
  for (i = 0; i < SECTORS_PER_PAGE; i++)
  {
    block_read (swap_block, sector + i,
                 (void *)((char *)kaddr + i * BLOCK_SECTOR_SIZE));
  }

  /* Reset the bitmap to be unused. */
  swap_reset_bitmap (slot_index);
}

void
setup_page (struct page* page, struct vm_entry *vme)
{
  page->vme = vme;
}

static void
_setup_page (struct page* page, void *kpage)
{
  page->kaddr = kpage;
  page->thread = thread_current ();
}

static void
page_page_free (struct page* page)
{
	void *kaddr = page->kaddr;

  /* Remove that page from the LRU_LIST. */
  page_remove_from_lru_list (page);

  /* should cleen page directory? */

  /* Free the page. */
  palloc_free_page (kaddr);

  /* Free the page structure. */
  free (page);
}

/* Find first 0 bit(UNUSED swap space) in the SWAP_BITMAP
   and then flip the bit into 1(will be used). */
static size_t
swap_find_empty_slot_and_flip (void)
{
  return bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
}

static void
swap_reset_bitmap (size_t slot_index)
{
  bitmap_reset (swap_bitmap, slot_index);
}


/****************************** MMAP related ******************************/
void
munmap_one_entry (struct mmap_file *mmfile)
{
  enum intr_level old_level;
  bool dirty = false;
	bool success = true;
	struct list_elem *e;
	struct vm_entry *vme;
	struct file *file;
	struct thread *cur = thread_current ();

  /* Remove VM_ENTRYs from list of MMAP_FILE & table of the current thread.
     And remove PAGE_TABLE_ENTRYs associating with them,
     then deallocate them. */
  while (!list_empty (&mmfile->vme_list))
  {
    e = list_pop_front (&mmfile->vme_list);
    vme = list_entry (e, struct vm_entry, mmap_elem);

    /* Remove it from the table of the current thread. */
    old_level = intr_disable ();
    success = delete_vme (&cur->vm, vme);
    intr_set_level (old_level);

    /* Check whether the page is mapped into physical memory. */
    if (vme->in_memory)
		{
    	/* If a mapping(virtual address -> physical address) exists */
    	/* Check whether the page is dirty or not. */
    	dirty = pagedir_is_dirty (cur->pagedir, vme->vaddr);

    	/* If the page is dirty, write it back to the original file. */
    	/* file_write_at (file, buffer, size, offset); */
    	if (dirty)
			{
				lock_acquire (&filesys_lock);
      	file_write_at (vme->file, vme->vaddr, vme->read_bytes, vme->offset);
				lock_release (&filesys_lock);
			}

      /* Free a page. */
      page_free (pagedir_get_page (cur->pagedir, vme->vaddr));

    	/* Remove PAGE_TABLE_ENTRY. */
    	old_level = intr_disable ();
    	pagedir_clear_page (cur->pagedir, vme->vaddr);
    	intr_set_level (old_level);
		}

    free ((void *)vme);
  }

  /* Close the file. */
  file = mmfile->file;
	lock_acquire (&filesys_lock);
  file_close (file);
	lock_release (&filesys_lock);

  /* Remove a MMAP_FILE from MMAP_LIST of the current thread
     and deallocate it.*/
  list_remove (&mmfile->elem);
  free (mmfile);

}

/* Delete all mmaped file associating with this thread. */
void
mmap_destroy (struct list* mmap_list)
{
  struct list_elem *e = NULL;
  struct mmap_file *mmfile = NULL;

  while (!list_empty (mmap_list))
  {
    e = list_pop_front (mmap_list);
    mmfile = list_entry (e, struct mmap_file, elem);
    munmap_one_entry (mmfile);
  }
}

/* Create MMAP_FILE and set up its members (mapping id, file object, list).
   And then insert it into MMAP_LIST of the current process descriptor.
   If success, return the MMAP_FILE. Otherwise, return NULL. */
struct mmap_file *
alloc_mmap_file (struct file* file)
{
  enum intr_level old_level;
  struct mmap_file *mmfile =
                   (struct mmap_file *) malloc (sizeof (struct mmap_file));
  if (mmfile == NULL)
    return NULL;

  /* Set up its members. */
  mmfile->file = file;
  list_init (&mmfile->vme_list);

  /* Insert MMFILE into MMAP_LIST of the current process descriptor. */
  old_level = intr_disable ();
  mmfile->id = thread_current ()->next_map_id++;
  list_push_back (&thread_current ()->mmap_list, &mmfile->elem);
  intr_set_level (old_level);

  return mmfile;
}

/* Create VM_ENTRYs for MMAP, and set up them.
   Return true if success, return false otherwise. */
bool
mmap_alloc_vm_entry (struct mmap_file *mmfile, void *addr)
{
  struct vm_entry *vme;
  struct file *file = mmfile->file;
  size_t read_bytes = file_length (file);
  size_t page_read_bytes;     /* Size of bytes to be read to a page. */
  size_t page_zero_bytes;     /* Size of bytes to be filled with zero. */
  off_t offset = 0;
  bool success = true;

  while (read_bytes > 0)
  {
    /* Calculate how to fill this page. */
    /* For fragmented page, fill the unused fraction of page with zero. */
    page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    page_zero_bytes = PGSIZE - page_read_bytes;

    /* Load file data into memory by demanding paging. */
    /* Create VM_ENTRY. */
    vme = (struct vm_entry *) malloc (sizeof (struct vm_entry));
    if (vme == NULL)
    {
      success = false;
      break;
    }

    /* Set up VM_ENTRY members. */
    setup_vm_entry (vme, VM_FILE, true, false, addr,
                    file, offset, page_read_bytes, page_zero_bytes);
    /* Insert vm_entry to hash table. */
    if (!insert_vme (&thread_current ()->vm, vme))
    {
      free (vme);
      success = false;
      break;
    }

    /* Insert vm_entry to list VME_LIST of MMAP_FILE structure. */
    list_push_back (&mmfile->vme_list, &vme->mmap_elem);

    addr = (void *) ((char *) addr + PGSIZE);
    offset += page_read_bytes;
    read_bytes -= page_read_bytes;
  }

  return success;
}

#endif
