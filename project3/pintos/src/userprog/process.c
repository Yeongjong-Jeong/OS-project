#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static int count_argc (char*);
static void set_up_stack_intr_frame (int, char*, char*, void **);
static bool install_page (void *upage, void *kpage, bool writable);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  struct thread *cur, *child;
  char *fn_copy, *thread_name, *save_ptr;
  char _file_name[strlen(file_name)+1];
  enum intr_level old_level;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
  strlcpy (_file_name, file_name, sizeof(_file_name));

  /* Parse a command-line string
     which is composed of a file_name and arguments for running the file.
     And from above, get program name. */
  thread_name = strtok_r (_file_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (thread_name, PRI_DEFAULT, start_process, fn_copy);

  /* Fail to create a process. */
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);
  /* Parent process should wait until it knows the child process has 
     successfully created and the binary file is successfully loaded. */
  else
  {
    cur = thread_current ();

		old_level = intr_disable ();
    /* wait until the child process load the binary file successfully. */
    sema_down (&cur->sema_exec); 
		intr_set_level (old_level);

    /* Finds the child process just created. */
    child = thread_find_tid (tid);

    ASSERT (child != NULL);

    /* The child process fails to load the program, so deallocate it. */
    if (child->load_status == 0)
    {
      thread_deallocate_child_process (child);
      return -1;
    }
  }

  return tid;
}

/* A thread function that loads a user process and starts it running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  char duplicate_file_name[strlen (file_name) + 1];
  char *thread_name, *save_ptr;
  struct intr_frame if_;
  bool success;
  int argc;

  /* Parse the command-line string. */
  strlcpy (duplicate_file_name, file_name, sizeof (duplicate_file_name));
  argc = count_argc (duplicate_file_name);
  thread_name = strtok_r (duplicate_file_name, " ", &save_ptr);

  /* Initialize the hash table. */
  vm_init (&thread_current ()->vm);
  /* Initialize the list MMAP_LIST of MMAP_FILEs. */
  list_init (&thread_current()->mmap_list);
  /* Initialize the map_id to be given to the new mmap_file structure. */
  thread_current ()->next_map_id = 1;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (thread_name, &if_.eip, &if_.esp);
  /* if success, stack for the interrupt frame is allocated, 
     so if_.esp points to the stack of the interrupt frame. */

	/* The process successfully load the binary file. */
  if (success)
    thread_current ()->load_status = 1;

  /* Notify the parent process
     that the child process was loaded successfully. */
  sema_up (&thread_current ()->parent->sema_exec);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) 
    thread_exit ();

  /* Set up stack - push the command-line arguments into user stack. */
	if (strlen(save_ptr) == 0)
	{
		set_up_stack_intr_frame (argc, thread_name, NULL, &if_.esp);
	}
	else
	{
  	argc = count_argc (save_ptr) + 1;
  	set_up_stack_intr_frame (argc, thread_name, save_ptr, &if_.esp);
	}

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int
process_wait (tid_t child_tid UNUSED) 
{
  struct thread *child;
  enum intr_level old_level;
  int child_exit_status;

  /* Validates the process id of the child process
     which the current process is waing for. */
  child = validate_child_pid (child_tid);
  /* If the tid is not valid, return -1. */
  if (child == NULL)
    return -1;

  /* If the child process is not terminated, wait. */
  if (child->status != THREAD_CHILD_WAIT)
	{
	 sema_down (&child->sema_wait);
	}
  /* FYI: The child process can already be terminated
     before call process_wait (). */
  /* Removes the terminated child process
     from the children list and deallocates it. */
  old_level = intr_disable ();
  list_remove (&child->child_elem);
	list_remove (&child->allelem);
  intr_set_level (old_level);

  child_exit_status = child->exit_status;

  /* Deallocates the descriptor of the child process. */
  // ASSERT (child != thread_current ());
  palloc_free_page (child);

  /* Returns the exit status of the child process just terminated. */
  /* FYI: the exit status could be -1, because of termination by kernel. */
  return child_exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Delete all mmaped file associating with this thread. */
  mmap_destroy (&cur->mmap_list);
  /* Delete all VM_ENTRYs associating with this thread. */
  vm_destroy (&cur->vm);
	/* Delete all pages associating with this thread. */
	page_destroy (cur);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  /* Allows modification of the current binary file. */
	if (cur->opened_file != NULL)
	{
		file_allow_write (cur->opened_file);
  	file_close (cur->opened_file);
	}
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* When page fault occurs, allocate physical memory.
   Load file in the disk to physical memory.
   Use load_file (void *kaddr, struct vm_entry *vme)
   Update the associated page table entry after loading into physical memory.
   Use static bool install_page (void *upage, void *kpage, bool writable) */
bool
handle_mm_fault (struct vm_entry *vme)
{
  bool success = false;
  struct page *page = page_alloc (PAL_USER | PAL_ZERO);
  uint8_t *kpage = page->kaddr;

  if (kpage == NULL)
    return false;

  switch (vme->type)
  {
    case VM_BIN:
    {
      success = load_file (kpage, vme);
      break;
    }
    case VM_FILE:
    {
      success = load_file (kpage, vme);
      break;
    }
    case VM_ANON:
    {
      swap_read_from_disk (vme->swap_index, kpage);
      success = true;
      break;
    }
    case VM_STACK_GROWTH:
    {
      vme->type = VM_ANON;
      success = true;
      break;
    }
  }

  if (!success)
  {
    page_free (kpage);
    return success;
  }

  success = install_page (vme->vaddr, kpage, vme->writable);

  if (!success)
  {
    page_free (kpage);
    return success;
  }

  /* Successfully load a file & install a page table entry. */
  vme->in_memory = true;
  /* Setup the member VME of the PAGE entry. */
  setup_page (page, vme);
	
  return success;
}

/* Count the number of arguments in ARG. */
int
count_argc (char *arg)
{
  int count = 0;
  char *pos = arg;
  while ((arg = strchr (arg, ' ')) != NULL)
  {
    /* when multiple spaces ' ' appears sequentially */
    if (pos == arg)
    {
      arg++;
      pos = arg;
    }
    else
    {
      count++;
      arg++;
      pos = arg;
    }
    
    /* when the string ends with space ' '. */
    if (*arg == '\0')
      count--;
  }
  count++;

  return count;
}

/* Parse the User program arguments
   and pass the arguments on user stack of new process. */
void
set_up_stack_intr_frame (int argc, char* file_name, char* args,
                         void** stackpointer)
{
  int size_token, padding;
  int total_input_size = 0;
  char *token, *save_ptr = NULL;
  void *argv[argc+1];
  int i = 0;

  /* Parse the arguments. */
  argv[i] = (void*)file_name;
  i++;
	if (args == NULL)
		i--;
	else
	{
  	for (token = strtok_r (args, " ", &save_ptr); token != NULL;
    	   token = strtok_r (NULL, " ", &save_ptr))
  	{
    	argv[i] = (void*)token;
    	i++;
 	 	}
	}

  /* Push the arguments to the user stack.
     And sums up the total bytes of arguments. */
  for (i=argc-1; i>=0; i--)
  {
    size_token = strlen ((char*)argv[i]) + 1;
    if (size_token == 1)
    {
      argc--;
      continue;
    }
    total_input_size += size_token;

    *(char**)stackpointer -= size_token;
    argv[i] = memcpy (*stackpointer, argv[i], size_token);
  }
  /* argv[argc] = 0 */
  argv[argc] = (void*)0;

  /* Zero padding to be a multiple of 4 bytes. */
  padding = (total_input_size % 4) ? 4 - (total_input_size % 4) : 0;
  *(char**)stackpointer -= padding;
  memset (*stackpointer, 0, (size_t)padding);

  /* Push the pointers to the arguments which are pushed to the user stack
   * on the user stack*/
  /* argv[argc] ~ argv[0] */
  for (i=argc; i>=0; i--)
  {
    *(char**)stackpointer -= sizeof(char*);
    memcpy (*stackpointer, &argv[i], sizeof(void*));    
  }

  /* Push the argv on the user stack. */
  argv[0] = *stackpointer;
  *(char**)stackpointer -= sizeof(char**);
  memcpy (*stackpointer, &argv[0], sizeof(char**));
  /*Push the argc on the user stack. */
  *(char**)stackpointer -= sizeof(int);
  memcpy (*stackpointer, &argc, sizeof(int));
  /* Push the return address(fake address) on the user stack. */
  *(char**)stackpointer -= sizeof(void*);
  memset (*stackpointer, 0, sizeof(void*));
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
	enum intr_level old_level;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
	lock_acquire (&filesys_lock);
  file = filesys_open (file_name);

  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }	

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;
	
	/* Prohibit modification of the currently loaded binary file. */
	old_level = intr_disable ();
	t->opened_file = file;
	file_deny_write (file);	
	intr_set_level (old_level);

	lock_release (&filesys_lock);
	success = true;
	return success;

 done:
  /* We arrive here if the load is not successful. */
  file_close (file);
	lock_release (&filesys_lock);
  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
	struct vm_entry *vme;
	bool success = false;

  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Create VM_ENTRY. */
      vme = (struct vm_entry *) malloc (sizeof (struct vm_entry));
      if (vme == NULL)
        return false;

      /* Set up VM_ENTRY members. */
      setup_vm_entry (vme, VM_BIN, writable, false, upage,
                      file, ofs, page_read_bytes, page_zero_bytes);
      /* Using insert_vme (), add vm_entry to hash table. */
      success = insert_vme (&thread_current ()->vm, vme);

      if (!success)
        return false;
      /* Automatically removes the early produced vm_entry
         at process_exit(). */

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;
  struct vm_entry *vme;
  struct page *page;

  page = page_alloc (PAL_USER | PAL_ZERO);
  kpage = page->kaddr;

  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        page_free (kpage);
    }
 
  if (success)
  {
    /* Create VM_ENTRY. */
    vme = (struct vm_entry *) malloc (sizeof (struct vm_entry));

    /* Set up VM_ENTRY members. */
    setup_vm_entry (vme, VM_ANON, true, true,
                    ((uint8_t *) PHYS_BASE) - PGSIZE, NULL, 0, 0, 0);

    /* Set up PAGE member VME. */
    setup_page (page, vme);

    /* Using insert_vme (), add vm_entry to hash table. */
    success = insert_vme (&thread_current ()->vm, vme);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}


