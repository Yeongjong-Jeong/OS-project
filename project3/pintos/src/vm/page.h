#ifdef USERPROG

#ifndef PAGE_H
#define PAGE_H

#include <hash.h>
#include "filesys/off_t.h"
// #include <stdint.h>
// #include <debug.h>

#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2

/* A virtual memory entry for user process.
   Structure that separates logical and physical addresses
   so that only pages that are "required" are loaded. */
struct vm_entry
{
  uint8_t type;                 /* Type of memory. */
  bool writable;                /* Read/Write permission. */
  bool in_memory;               /* Flag. Is it in memory? Maybe Shared. */
  void *vaddr;                  /* Virtual page number. */

  struct file* file;            /* Reference to the file object. */
  off_t offset;                	/* File offset. */
  size_t read_bytes;            /* Amount of data in the page. */
  size_t zero_bytes;            /* Zero byte to pad at the end. */

  struct hash_elem elem;        /* Hash Table element. */
  /* Location in the swap area. */ /* Swapping. */
  /* Memory Mapped file List element. */
};

/* Initialize the hash table storing VM_ENTRYs. */
void vm_init (struct hash* vm);

/* Delete the hash table. */
void vm_destroy (struct hash* vm);

/* Search vm_entry corresponding to VADDR
   in the address space of the current process. */
struct vm_entry* find_vme (void * vaddr);

/* Insert VM_ENTRY to hash table. */
bool insert_vme (struct hash *vm, struct vm_entry *vme);

/* Delete VM_ENTRY from hash table. */
bool delete_vme (struct hash *vm, struct vm_entry *vme);

/* Load the file page from the disk to physical memory. */
bool load_file (void *kaddr, struct vm_entry *vme);

#endif
#endif
