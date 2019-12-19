#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "lib/user/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#define USER_VADDR_LOW_BOUND ((void*) 0x08048000)
#define FAILURE -1

static void syscall_handler (struct intr_frame *);

static bool check_user_address_at_stack (void *uaddr);
static void check_user_address (void *uaddr);
static void check_user_buffer (void *buffer, unsigned size, bool to_write);

static void copy_args (void *user_stack, int *args, int arg_num);

static int fdt_insert (struct file *);
static struct file *fdt_find (int fd);
static void fdt_remove (int fd);

static struct file *mmap_check (int fd, void *addr);

void
syscall_init (void)
{
	/* Initialize the global lock FILESYS_LOCK. */
	lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* System call handler. */
static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int system_call_number;
  int args[3];    /* Arguments to be passed to the system call. */

  /* System call number. */
  system_call_number = *(int *) f->esp;

  /* Store a stack pointer into the current thread descriptor.
     Because when the page fault occurs due to stack growth in kernel mode
     we cannot receive the correct stack pointer address
     from interrupt frame. */
	thread_current ()->esp = f->esp;
  
  switch (system_call_number)
  {
    case SYS_HALT:                   /* Halt the operating system. */
    {
      halt ();
      break;
    }
    case SYS_EXIT:                   /* Terminate this process. */
    {
			/* copy arguments. */
      copy_args (f->esp, args, 1);
      exit (args[0]);
      break;
    }
    case SYS_EXEC:                   /* Start another process. */
    {
      copy_args (f->esp, args, 1);
      f->eax = exec ((const char *) args[0]);
      break;
    }
    case SYS_WAIT:                   /* Wait for a child process to die. */
    {
      copy_args (f->esp, args, 1);
      f->eax = wait ((pid_t) args[0]);
      break;
    }
    case SYS_CREATE:                 /* Create a file. */
    {
      copy_args (f->esp, args, 2);
      f->eax = create ((const char *) args[0], (unsigned) args[1]);
      break;
    }
    case SYS_REMOVE:                 /* Delete a file. */
    {
      copy_args (f->esp, args, 1);
      f->eax = remove ((const char *) args[0]);
      break;
    }
    case SYS_OPEN:                   /* Open a file. */
    {
      copy_args (f->esp, args, 1);
      f->eax = open ((const char *) args[0]);
      break;
    }
    case SYS_FILESIZE:               /* Obtain a file's size. */
    {
      copy_args (f->esp, args, 1);
      f->eax = filesize ((int) args[0]);
      break;
    }
    case SYS_READ:                   /* Read from a file. */
    {
      copy_args (f->esp, args, 3);
      f->eax = read ((int) args[0], (void *) args[1], (unsigned) args[2]);
      break;
    }
    case SYS_WRITE:                  /* Write to a file. */
    {
      copy_args (f->esp, args, 3);
      f->eax = write (args[0], (void *) args[1], (unsigned) args[2]);
      break;
    }
    case SYS_SEEK:                   /* Change position in a file. */
    {
      copy_args (f->esp, args, 2);
      seek ((int) args[0], (unsigned) args[1]);
      break;
    }
    case SYS_TELL:                   /* Report current position in a file. */
    {
      copy_args (f->esp, args, 1);
      f->eax = tell ((int) args[0]);
      break;
    }
    case SYS_CLOSE:                  /* Close a file. */
    {
      copy_args (f->esp, args, 1);
      close ((int) args[0]);
      break;
    }
    case SYS_MMAP:                    /* Map a file into memory. */
    {
      copy_args (f->esp, args, 2);
      f->eax = mmap ((int) args[0], (void *) args[1]);
      break;
    }
    case SYS_MUNMAP:                  /* Remove a memory mapping. */
    {
      copy_args (f->esp, args, 1);
      munmap ((mapid_t) args[0]);
      break;
    }
    default:
    {
      thread_exit ();
      break;
    }
  }
}


/* Shutdown pintos. */
void
halt (void)
{
  shutdown_power_off ();
}

/* Exit the current process. */
void
exit (int status)
{
  struct thread* cur = thread_current ();
	enum intr_level old_level = intr_disable ();

  /* Save exit status at process descriptor. */
  cur->exit_status = status;
	intr_set_level (old_level);

  /* print message "Name of process: exit(status)". */
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit ();
}

/* Create child process and execute program corresponds to CMD_LINE. */
pid_t
exec (const char *cmd_line)
{
  /* Check whether the given string is valid or not. */
  check_user_buffer ((void *) cmd_line, strlen(cmd_line) + 1, false);
  
  /* Pinning the page associating with the given user address. */
	set_pin_on_buffer (cmd_line, strlen (cmd_line) + 1);

  pid_t pid = process_execute (cmd_line);

	reset_pin_on_buffer (cmd_line, strlen (cmd_line) + 1);

  return pid;
}

/* Wait for termination of child process whose process id is pid. */
int
wait (pid_t pid)
{
  return process_wait (pid);
}

/* Create a file which have size of INITIAL_SIZE.
   Return true if it is successed, or false if it is not. */
bool
create (const char *file, unsigned initial_size)
{
	bool success;

  /* If the user pass the null pointer, exit(-1). */
	if (file == NULL)
		exit (FAILURE);

  /* Checks the address passed by the user. */
  /* If it's not valid, exit(-1). */
	check_user_buffer ((void*)file, strlen (file) + 1, false);

  /* If the file name is empty, exit(-1). */
	if (strlen (file) == 0)
		exit (FAILURE);
	
  /* Pinning the page associating with the given user address. */
	set_pin_on_buffer (file, strlen(file) + 1);

  /* Use global lock to avoid the race condtion on file. */
	lock_acquire (&filesys_lock);
  success = filesys_create (file, initial_size);
	lock_release (&filesys_lock);

	reset_pin_on_buffer (file, strlen(file) + 1);

	return success;
}

/* Remove a file whose name is FILE.
   return true if it is successed or false it is not. 
   File is removed regardless of whether it is open or closed. */
bool
remove (const char *file)
{
	bool success;

  /* If the user pass the null pointer, exit(-1). */
	if (file == NULL)
		exit (FAILURE);

  /* Checks the address passed by the user. */
  /* If it's not valid, exit(-1). */
	check_user_buffer ((void*)file, strlen (file) + 1, false);

  /* If the file name is empty, exit(-1). */
	if (strlen (file) == 0)
		exit (FAILURE);

  /* Pinning the page associating with the given user address. */
	set_pin_on_buffer (file, strlen(file) + 1);

  /* File is removed regardless of whether it is open or closed. */
  /* Use global lock to avoid the race condtion on file. */
	lock_acquire (&filesys_lock);
  success = filesys_remove ((const char*)file);
	lock_release (&filesys_lock);

	reset_pin_on_buffer (file, strlen(file) + 1);

	return success;
}

/* Open the file corresponds to path in FILE.
   Return its file descriptor number if it opens successfully.
   Return -1 if it is not. */
int
open (const char *file)
{
  struct file *f;

  /* If the user pass the null pointer, exit(-1). */
	if (file == NULL)
		exit (FAILURE);

  /* Checks the address passed by the user. */
  /* If it's not valid, exit(-1). */
	check_user_buffer ((void *)file, strlen (file) + 1, false);

  /* If the file name is empty, exit(-1). */
	if (strlen (file) == 0)
		return FAILURE;

  /* Pinning the page associating with the given user address. */
	set_pin_on_buffer (file, strlen(file) + 1);

  /* Use global lock to avoid the race condtion on file. */
	lock_acquire (&filesys_lock);
  f = filesys_open (file);
	lock_release (&filesys_lock);

	reset_pin_on_buffer (file, strlen(file) + 1);

  /* fails to open the file. */
	if (f == NULL)
		return FAILURE;

  /* Return the file descriptor number of the file just opened. */
  return fdt_insert (f);
}

/* Return the size, in bytes, of the file opened as FD.
 * If FD is not vaild, exit (-1). */
int
filesize (int fd)
{
  struct thread *cur = thread_current ();
	int size;

  if (fd == 0 || fd == 1 || fd >= FDT_SIZE)
    exit (FAILURE);
  if (cur->fdt[fd] == NULL)
    exit (FAILURE);

	/* file size should not be changed. */
	lock_acquire (&filesys_lock);
  size = file_length (cur->fdt[fd]);
	lock_release (&filesys_lock);

	return size;
}

/* Read SIZE bytes from the file opened as FD into BUFFER.
 * Return the number of bytes actually read, or -1 if it fails. */
int
read (int fd, void* buffer, unsigned size)
{
  struct thread *cur;
	unsigned i;
	unsigned size_read;

  /* Check whether the buffer passed by the user is valid
     and also check whether the given user address has
     write permission. */
	check_user_buffer (buffer, size, true);

  /* Invalid FD. */
  if (fd == 1 || fd >= FDT_SIZE)
    return FAILURE;

  /* FD is Standard Input Stream. */
  if (fd == 0)
	{
    /* Pinning the page associating with the given user address. */
		set_pin_on_buffer (buffer, size);

		for (i = 0; i < size ; i++)
			*((uint8_t *)buffer + i) = input_getc();

		reset_pin_on_buffer (buffer, size);
		return size;
	}

  /* If the current process doesn't have FD, return -1. */
  cur = thread_current ();
  if (cur->fdt[fd] == NULL)
    return FAILURE;

  /* Pinning the page associating with the given user address. */
	set_pin_on_buffer (buffer, size);

	lock_acquire (&filesys_lock);
  size_read = file_read (cur->fdt[fd], buffer, size);
	lock_release (&filesys_lock);

	reset_pin_on_buffer (buffer, size);

	return size_read;
}

/* Writes SIZE bytes from BUFFER to the opened file as FD.
   Returns the number of bytes actually written.
   If FD is invalid, return -1. */
int
write (int fd, const void *buffer, unsigned size)
{
  struct thread *cur;
	int size_write;

  /* Check whether the buffer passed by the user is valid. */
	check_user_buffer ((void*)buffer, size, false);

  if (fd <= 0 || fd >= FDT_SIZE)
    exit (FAILURE);

  /* FD is Standard Output Stream. */
  if (fd == 1)
  {
    /* Pinning the page associating with the given user address. */
		set_pin_on_buffer (buffer, size);

    putbuf ((const char*)buffer, size);
		reset_pin_on_buffer (buffer, size);
    return size;
  }
	
  /* If the current process doesn't have FD, return -1. */
  cur = thread_current ();
  if (cur->fdt[fd] == NULL)
    return FAILURE;

  /* Pinning the page associating with the given user address. */
	set_pin_on_buffer (buffer, size);

	lock_acquire (&filesys_lock);
  size_write = file_write (cur->fdt[fd], buffer, size);
	lock_release (&filesys_lock);

	reset_pin_on_buffer (buffer, size);

	return size_write;
}

/* Changes the next byte to be read or written
   in opened file FD to POSITION.
   If the FD is not valid, EXIT(-1). */
void
seek (int fd, unsigned position)
{
  struct thread *cur = thread_current ();

  /* FD is not valid. */
  if (fd <= 1 || fd >= FDT_SIZE)
		exit (FAILURE);

  /* FD is not valid. */
  if (cur->fdt[fd] == NULL)
		exit (FAILURE);
	
	lock_acquire (&filesys_lock);
  file_seek (cur->fdt[fd], position);
	lock_release (&filesys_lock);
}

/* Return the position of the next byte to be read or written
   in opened file fd. */
unsigned
tell (int fd)
{
  struct thread *cur = thread_current ();
	unsigned position;

  /* FD is not valid. */
	if (fd <= 1 || fd >= FDT_SIZE)
		exit (FAILURE);

  /* FD is not valid. */
  if (cur->fdt[fd] == NULL)
		exit (FAILURE);

	lock_acquire (&filesys_lock);
  position = file_tell (cur->fdt[fd]);
	lock_release (&filesys_lock);
	return position;
}

/* Close file descriptor FD. */
void
close (int fd)
{
  fdt_remove (fd);
}

/* Map a file into memory.
 * Returns mapping_id if success, return -1 otherwise. */
int
mmap (int fd, void *addr)
{
  bool success = false;
	enum intr_level old_level;
  struct file *file, *new_file;
  struct mmap_file * mmfile;
  
  file = mmap_check (fd, addr);
  if (file == NULL)
    return FAILURE;

  /* Opens a new file (reproduce the original file).
     Make the mmaped memory valid even if the file close. */
  new_file = file_reopen (file);
  if (new_file == NULL)
    return FAILURE;

  mmfile = alloc_mmap_file (new_file);
  if (mmfile == NULL)
  {
    file_close (new_file);
    return FAILURE;
  }

  /* Create VM_ENTRYs, set up their members, and insert it into vm table.
     Also, insert them into list VME_LIST of MMAP_FILE structure. 
     Return value is boolean value success(true) or failure(false). */
	old_level = intr_disable ();
  success = mmap_alloc_vm_entry (mmfile, addr);
	intr_set_level (old_level);

  if (!success)
  {
    file_close (new_file);
    return FAILURE;
  }

  /* Return mapid */
  return mmfile->id;
}

/* Remove a memory mapping. */
void
munmap (mapid_t mapid)
{
  /* Unmap the mappings in the MMAP_LIST
     which has not been previously unmapped. */
  struct list *mmap_list = &thread_current ()->mmap_list;
  struct list_elem *e = NULL;
  struct mmap_file *mmfile = NULL;
  bool find = false;
	enum intr_level old_level;

  /* Find a MMAP_FILE whose map_id is MAPID. */
  for (e = list_begin (mmap_list); e != list_end (mmap_list);
       e = list_next (e))
  {
    mmfile = list_entry (e, struct mmap_file, elem);
    if (mmfile->id == mapid)
    {
      find = true;
      break;
    }
  }

  if (!find)
    return ;
	
  munmap_one_entry (mmfile);
}

/* Check whether the pointer passed by the user is
   in the allowable stack area for the user.
	 If the pointer is in that area, return true.
	 Otherwise, return false. */
static bool
check_user_address_at_stack (void *uaddr)
{
	void *MIN_LIMIT = (void *) (0xC0000000 - 8 * 1024 * 1024);
	void *MAX_LIMIT = (void *) (0xC0000000);

	if (uaddr <= MAX_LIMIT && uaddr >= MIN_LIMIT)
		return true;
	return false;
}

/* Checks whether the pointer passed by the user is valid.
   If it not, EXIT(-1). */
static void
check_user_address (void* uaddr)
{
  if (uaddr == NULL)
    exit (FAILURE);

  /* Check whether the pointer is in the right memory region
     that is assigned for user or not. If not, exit(-1). */
  if (!is_user_vaddr (uaddr))
    exit (FAILURE);
  if (uaddr < USER_VADDR_LOW_BOUND)
    exit (FAILURE);

	/* Check whether there's the corresponding VM_ENTRY
     with the user virtual address or not.
		 If not, it could be in the possible stack area of the user.
		 So check whether it is. If it's not, exit(-1). */
  if (find_vme (uaddr) == NULL)
	{
		if (!check_user_address_at_stack (uaddr))
    	exit (FAILURE);
	}
}

/* Checks whether the BUFFER passed by the user is valid
   and also checks whether the address has the given write permission.
   If it not, EXIT(-1). */
static void
check_user_buffer (void* buffer, unsigned size, bool to_write)
{
	unsigned i;
	struct vm_entry *vme;

  /* The size of buffer can be larger than the size of a page. */
	for (i = 0; i < size; i = i + PGSIZE) /* i = i + PGSIZE */
  {
    /* Check whether the buffer is valid user virtual address. */
		check_user_address ((void*) ((char*) buffer + i));

    /* Check whether the address given as buffer is writable or not.
			 If the corresponding VM_ENTRY doesn't exist,
			 then check whether the buffer is
			 in the possible stack area where the user can expand.
       If VM_ENTRY exists, check the write permission from the VM_ENTRY.
			 If there's no permission, exit(-1). */
		if (to_write)
    {
			vme = find_vme (buffer + i);
			if (vme == NULL)
			{
				if (!check_user_address_at_stack (buffer + i))
					exit (FAILURE);
			}
			else
			{
      	if (vme->writable != to_write)
        	exit (FAILURE);
			}
    }
  }

	check_user_address ((void*) ((char*) buffer + size - 1));
  if (to_write)
  {
		vme = find_vme (buffer + size -1);
		if (vme == NULL)
		{
			if (!check_user_address_at_stack (buffer + size - 1))
				exit (FAILURE);
		}
		else
		{
    	if (vme->writable != to_write)
      	exit (FAILURE);
		}
  }
}

/* Copy arguments on user stack at kernel. */
static void
copy_args (void* user_stack, int *args, int arg_num)
{
  int i;
  int *uaddr = NULL;

  for (i=0; i<arg_num; i++)
  {
    uaddr = (int*)user_stack;
    uaddr += (1 + i);
    check_user_address ((void*)uaddr);
    memcpy (args+i, uaddr, sizeof(int));
    // printf ("Copy arguments: %d\n", args[i]);
  }

}

/* Allocate the file descriptor to a file. */
static int
fdt_insert (struct file *f)
{
  struct thread* cur = thread_current ();
	enum intr_level old_level;
  int i;

  for (i = 2; i < (cur->fdt_max + 2); i++)
  {
    if (cur->fdt[i] == NULL)
    {
			old_level = intr_disable ();
      cur->fdt[i] = f;
			if (i > cur->fdt_max)
				cur->fdt_max = i;
			intr_set_level (old_level);
      return i;
    }
  }

  return -1;
}

/* Finds the FD of the current process. */
static struct file *
fdt_find (int fd)
{
  return thread_current ()->fdt[fd];
}

/* Deallocates the file descriptor FD. */
static void
fdt_remove (int fd)
{
  struct thread *cur = thread_current ();
	enum intr_level old_level;

  if (fd <= 1 || fd >= FDT_SIZE)
		exit (FAILURE);

  if (cur->fdt[fd] == NULL)
		exit (FAILURE);

  /* close file */
	/* lock acquire? */
	lock_acquire (&filesys_lock);
  file_close (cur->fdt[fd]);
	lock_release (&filesys_lock);

  /* Resets FDT entry. */
	old_level = intr_disable ();
  cur->fdt[fd] = NULL;
	intr_set_level (old_level);
}

/* Check the validity before running MMAP ().
   MMAP error case check.
     Return value is a file descriptor associating with FD.
     Test includes :
     (1) FD should be valid.
     (2) addr should not be 0.
     (3) addr should not be in used. (need consecutive memory block)
     (4) find the file descriptor associating with FD.
     (5) check the size of file is larger than 0.
     If test fails, return NULL. */
static struct file *
mmap_check (int fd, void *addr)
{
	struct file *file = NULL;
  struct vm_entry *vme = NULL;
  size_t offset = 0;
	size_t read_bytes = 0;

  /* Invalid FD. STDIN and STDOUT are not mappable. */
  if (fd == 0 || fd == 1 || fd >= FDT_SIZE)
    return NULL;

  /* Addr is 0. (Because this area is reserved for PintOS. */
  if (addr == (void *) 0)
    return NULL;

	/* Addr should be on the user virtual address.
		 Addr should be aligned. */
	if (!is_user_vaddr (addr) || addr < USER_VADDR_LOW_BOUND 
			|| (uint32_t) addr % PGSIZE != 0)
		return NULL;

  /* Find the file structure associating with FD. */
  file = fdt_find (fd);
  if (file == NULL)
    return NULL;             /* No such file. */

  read_bytes = file_length (file);
  /* If the file size is 0, return -1. */
  if (read_bytes == 0)
    return NULL;

  /* If ADDRs should not be in used. If not, return -1.
	   (need consecutive free memory) */
  for (offset = 0; offset < read_bytes; offset += PGSIZE)
  {
    vme = find_vme ((void *)((char *) addr + offset));
    if (vme != NULL)
      return NULL;
  }
  vme = find_vme ((void *)((char *) addr + read_bytes - 1));
  if (vme != NULL)
    return NULL;

  /* All test cases passes, return file descriptor. */
  return file;
}

