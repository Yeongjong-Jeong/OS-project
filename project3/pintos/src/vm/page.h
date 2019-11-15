#ifdef USERPROG

#ifndef PAGE_H
#define PAGE_H

#include <hash.h>
#include "filesys/off_t.h"
#include "userprog/syscall.h"
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
  struct list_elem mmap_elem;   /* Mmap list element. */
};

/* Data Structure containing information from mapped files. */
struct mmap_file
{
  mapid_t id;                   /* Mapping id. */
  struct file *file;            /* Mapping file object. */
  struct list_elem elem;        /* MMAP_FILE list element. */
  struct list vme_list;         /* VM_ENTRY list. */
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

void setup_vm_entry (struct vm_entry *, uint8_t, bool, bool,
                     void *, struct file*, off_t, size_t, size_t);



/* Load the file page from the disk to physical memory. */
bool load_file (void *kaddr, struct vm_entry *vme);

void munmap_one_entry (struct mmap_file *mmfile);

/* Delete all mmaped file associating with this thread. */
void mmap_destroy (struct list* mmap_list);

/* Create MMAP_FILE and set up its members (mapping id, file object, list).
   And then insert it into MMAP_LIST of the current process descriptor.
   If success, return the MMAP_FILE. Otherwise, return NULL. */
struct mmap_file *alloc_mmap_file (struct file* file);

/* Create VM_ENTRYs for MMAP, and set up them.
   Return true if success, return false otherwise. */
bool mmap_alloc_vm_entry (struct mmap_file *mmfile, void *addr);

#endif
#endif
