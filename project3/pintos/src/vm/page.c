#ifdef USERPROG

#include "vm/page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include <string.h>
// #include <debug.h>
// #include <stddef.h>
// #include <stdio.h>

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
  e->vaddr = uvaddr;
  e->file = file;
  e->offset = offset;
  e->read_bytes = read_bytes;
  e->zero_bytes = zero_bytes;
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
    if (pagedir_get_page (cur->pagedir, vme->vaddr))
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
