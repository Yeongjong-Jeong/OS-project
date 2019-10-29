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
static void check_user_address (void* uaddr);
static void check_user_buffer (void* buffer, unsigned size);
static void* uaddr_to_kaddr (void* uaddr);
static void copy_args (void* user_stack, int *args, int arg_num);
static int fdt_insert (struct file *);
static struct file *fdt_find (int fd);
static void fdt_remove (int fd);

void
syscall_init (void)
{
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
  system_call_number = *(int*)f->esp;
  
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
      f->eax = exec ((const char*)args[0]);
      break;
    }
    case SYS_WAIT:                   /* Wait for a child process to die. */
    {
      copy_args (f->esp, args, 1);
      f->eax = wait ((pid_t)args[0]);
      break;
    }
    case SYS_CREATE:                 /* Create a file. */
    {
      copy_args (f->esp, args, 2);
      f->eax = create ((const char*)args[0], (unsigned)args[1]);
      break;
    }
    case SYS_REMOVE:                 /* Delete a file. */
    {
      copy_args (f->esp, args, 1);
      f->eax = remove ((const char*)args[0]);
      break;
    }
    case SYS_OPEN:                   /* Open a file. */
    {
      copy_args (f->esp, args, 1);
      f->eax = open ((const char*)args[0]);
      break;
    }
    case SYS_FILESIZE:               /* Obtain a file's size. */
    {
      copy_args (f->esp, args, 1);
      f->eax = filesize ((int)args[0]);
      break;
    }
    case SYS_READ:                   /* Read from a file. */
    {
      copy_args (f->esp, args, 3);
      f->eax = read ((int)args[0], (void*)args[1], (unsigned)args[2]);
      break;
    }
    case SYS_WRITE:                  /* Write to a file. */
    {
      copy_args (f->esp, args, 3);
      f->eax = write (args[0], (void*)args[1], (unsigned)args[2]);
      break;
    }
    case SYS_SEEK:                   /* Change position in a file. */
    {
      copy_args (f->esp, args, 2);
      seek ((int)args[0], (unsigned)args[1]);
      break;
    }
    case SYS_TELL:                   /* Report current position in a file. */
    {
      copy_args (f->esp, args, 1);
      f->eax = tell ((int)args[0]);
      break;
    }
    case SYS_CLOSE:                  /* Close a file. */
    {
      copy_args (f->esp, args, 1);
      close ((int)args[0]);
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
  /* Converts the user virtual address to the physical kernel address. */
	void *kaddr = uaddr_to_kaddr ((void *)cmd_line);
  pid_t pid = process_execute ((const char *)kaddr);
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
	void *kaddr;
	bool success;

  /* If the user pass the null pointer, exit(-1). */
	if (file == NULL)
		exit (FAILURE);

  /* Checks the address passed by the user. */
  /* If it's not valid, exit(-1). */
	check_user_address ((void*)file);
	kaddr = uaddr_to_kaddr ((void *)file);

  /* If the file name is empty, exit(-1). */
	if (strlen (kaddr) == 0)
		exit (FAILURE);

  /* Use global lock to avoid the race condtion on file. */
	lock_acquire (&filesys_lock);
  success = filesys_create ((const char*)kaddr, initial_size);
	lock_release (&filesys_lock);
	return success;
}

/* Remove a file whose name is FILE.
   return true if it is successed or false it is not. 
   File is removed regardless of whether it is open or closed. */
bool
remove (const char *file)
{
	void *kaddr;
	bool success;

  /* If the user pass the null pointer, exit(-1). */
	if (file == NULL)
		exit (FAILURE);

  /* Checks the address passed by the user. */
  /* If it's not valid, exit(-1). */
	check_user_address ((void*)file);
	kaddr = uaddr_to_kaddr ((void *)file);

  /* If the file name is empty, exit(-1). */
	if (strlen (kaddr) == 0)
		exit (FAILURE);

  /* File is removed regardless of whether it is open or closed. */
  /* Use global lock to avoid the race condtion on file. */
	lock_acquire (&filesys_lock);
  success = filesys_remove ((const char*)kaddr);
	lock_release (&filesys_lock);
	return success;
}

/* Open the file corresponds to path in FILE.
   Return its file descriptor number if it opens successfully.
   Return -1 if it is not. */
int
open (const char *file)
{
  struct file *f;
	void *kaddr;

  /* If the user pass the null pointer, exit(-1). */
	if (file == NULL)
		exit (FAILURE);

  /* Checks the address passed by the user. */
  /* If it's not valid, exit(-1). */
	check_user_address ((void *)file);
	kaddr = uaddr_to_kaddr ((void *)file);

  /* If the file name is empty, exit(-1). */
	if (strlen (kaddr) == 0)
		return FAILURE;

  /* Use global lock to avoid the race condtion on file. */
	lock_acquire (&filesys_lock);
  f = filesys_open (kaddr);
	lock_release (&filesys_lock);

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
	void *kaddr;

  /* Check whether the buffer passed by the user is valid. */
	check_user_buffer (buffer, size);
	kaddr = uaddr_to_kaddr (buffer);

  /* Invalid FD. */
  if (fd == 1 || fd >= FDT_SIZE)
    return FAILURE;

  /* FD is Standard Input Stream. */
  if (fd == 0)
	{
		for (i = 0; i < size ; i++)
			*((uint8_t *)kaddr + i) = input_getc();
		return size;
	}

  /* If the current process doesn't have FD, return -1. */
  cur = thread_current ();
  if (cur->fdt[fd] == NULL)
    return FAILURE;

	lock_acquire (&filesys_lock);
  size_read = file_read (cur->fdt[fd], kaddr, size);
	lock_release (&filesys_lock);
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
	void *kaddr;

  /* Check whether the buffer passed by the user is valid. */
	check_user_buffer ((void*)buffer, size);
	kaddr = uaddr_to_kaddr ((void*)buffer);

  if (fd <= 0 || fd >= FDT_SIZE)
    exit (FAILURE);

  /* FD is Standard Output Stream. */
  if (fd == 1)
  {
    putbuf ((const char*)kaddr, size);
    return size;
  }
	
  /* If the current process doesn't have FD, return -1. */
  cur = thread_current ();
  if (cur->fdt[fd] == NULL)
    return FAILURE;

	lock_acquire (&filesys_lock);
  size_write = file_write (cur->fdt[fd], kaddr, size);
	lock_release (&filesys_lock);
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

/* Checks whether the pointer passed by the user is valid.
 * If it not, EXIT(-1). */
static void
check_user_address (void* uaddr)
{
  if (uaddr == NULL)
    exit (FAILURE);
  if (!is_user_vaddr (uaddr))
    exit (FAILURE);
  if (uaddr < USER_VADDR_LOW_BOUND)
    exit (FAILURE);
}

/* Checks whether the BUFFER passed by the user is valid.
 * If it not, EXIT(-1). */
static void
check_user_buffer (void* buffer, unsigned size)
{
	unsigned i;
	for (i = 0; i < size; i++)
		check_user_address ((void*) ((char*) buffer + i));
}

/* Converts the user virtual address to the kernel virtual address. */
static void*
uaddr_to_kaddr (void* uaddr)
{
	void *kaddr = NULL;
	
	/* check whether the user virtual address is valid. */
	check_user_address (uaddr);

	kaddr = pagedir_get_page (thread_current ()->pagedir, uaddr);

	/* the user virtual address is unmapped. */
	if (kaddr == NULL)
		exit (FAILURE);
	
	return kaddr;
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
