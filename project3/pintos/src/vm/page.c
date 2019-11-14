#ifdef USERPROG

#include "vm/page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
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

#endif
