#ifdef USERPROG

#ifndef PAGE_H
#define PAGE_H

#include <hash.h>
#include <bitmap.h>
#include "filesys/off_t.h"
#include "userprog/syscall.h"
#include "threads/palloc.h"
// #include <stdint.h>
// #include <debug.h>

/************************* Demanding page related *************************/
#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2
#define VM_STACK_GROWTH 3

/* A virtual memory entry for user process.
   Structure that separates logical and physical addresses
   so that only pages that are "required" are loaded. */
struct vm_entry
{
  uint8_t type;                 /* Type of memory. */
  bool writable;                /* Read/Write permission. */
  bool in_memory;               /* Flag. Is it in memory? */
	bool pin_flag;								/* Flag to prevent evicting the page. */

	void *vaddr;                  /* Virtual page number. */

  struct file* file;            /* Reference to the file object. */
  off_t offset;                	/* File offset. */
  size_t read_bytes;            /* Amount of data in the page. */
  size_t zero_bytes;            /* Zero byte to pad at the end. */

  size_t swap_index;            /* Location in the swap area. */

  struct hash_elem elem;        /* Hash Table element. */
  struct list_elem mmap_elem;   /* Mmap list element. */
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

/****************************** SWAP related ******************************/
/* The number of block sectors per a page. */
#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

/* A frame table (Global variable):
   manages physical pages in use as a list of pages.
   It contains one entry for each physical page frame
   that contains a user page.
   By choosing a page to evict when no frames are free,
   it allows PintOS to implement an eviction policy. */
struct list lru_list;

/* A frame table entry. */
struct page
{
  void *kaddr;                    /* Physical frame number. */
  struct vm_entry *vme;         /* Associated virtual address. */
  struct thread *thread;        /* Thread structure this page belongs to. */
  struct list_elem elem;         /* LRU field for list. */
};

/* A Global lock. 
   If one page fault requires I/O,
   the other page faults which require I/O should wait.
   If the other page faults that do not require I/O
   should be able to complete in the meantime. */
struct lock lru_lock;

/* Swap bitmap (Gloval variable):
   maintains swap partition.
   Each swap partition is managed per swap slot(4 KBytes). */
struct bitmap *swap_bitmap;
struct block *swap_block;
struct lock swap_lock;

void lru_init (void);
void page_destroy (struct thread *cur);
struct page *page_alloc (enum palloc_flags flag);
void page_free (void *kaddr);
void page_insert_to_lru_list (struct page* page);
void page_remove_from_lru_list (struct page* page);
void swap_init (void);
void setup_page (struct page *page, struct vm_entry *vme);
void swap_choose_victim_and_free_page (void);
void set_pin_on_addr (void *vaddr);
void set_pin_on_buffer (void *buffer, size_t size);
void reset_pin_on_addr (void *vaddr);
void reset_pin_on_buffer (void *buffer, size_t size);
size_t swap_write_to_disk (void *kaddr);
void swap_read_from_disk (size_t slot_index, void *kaddr);

/****************************** MMAP related ******************************/
/* Data Structure containing information from mapped files. */
struct mmap_file
{
  mapid_t id;                   /* Mapping id. */
  struct file *file;            /* Mapping file object. */
  struct list_elem elem;        /* MMAP_FILE list element. */
  struct list vme_list;         /* VM_ENTRY list. */
};

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

/************************* Stack Growth related *************************/
struct vm_entry *stack_grow (void *vaddr, void *esp);

#endif
#endif
