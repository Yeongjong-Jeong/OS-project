#include "userprog/syscall.h"
#include "userprog/process.h"
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
#define SUCCESS 0
#define FAILURE 1

static void syscall_handler (struct intr_frame *);
static void copy_args (void* user_stack, int *args, int arg_num);
static void copy_args_write (void* user_stack, int *args, int arg_num);
static int fdt_insert (struct file *);
static struct file *fdt_find (int fd);
static void fdt_remove (int fd);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int system_call_number;
  int args[3];

  // printf ("system call!\n");

  system_call_number = *(int*)f->esp;

  // printf ("System call number: %d\n", system_call_number);
  // hex_dump (f->esp, f->esp, PHYS_BASE - f->esp, true);

  // thread_exit ();
  
  switch (system_call_number)
  {
    case SYS_HALT:                   /* Halt the operating system. */
    {
      halt ();
      break;
    }
    case SYS_EXIT:                   /* Terminate this process. */
    {
      /* check validation of pointer to user stack
       * and other pointers on arguments */
      copy_args (f->esp, args, 1);
      exit (args[0]);
      break;
    }
    case SYS_EXEC:                   /* Start another process. */
    {
      copy_args (f->esp, args, 1);
      exec ((const char*)args[0]);
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
      copy_args_write (f->esp, args, 3);
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
void halt (void)
{
  shutdown_power_off ();
}

/* Exit the current process. */
void exit (int status)
{
  struct thread* cur = thread_current ();
  /* Save exit status at process descriptor. */
  cur->exit_status = status;

  /* print message "Name of process: exit(status)". */
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit ();
}

/* Create child process and execute program corresponds to CMD_LINE. */
pid_t exec (const char *cmd_line)
{
  pid_t pid = process_execute (cmd_line);
  return pid;
}

/* Wait for termination of child process whose process id is pid. */
int wait (pid_t pid)
{
  return process_wait (pid);
}

bool create (const char *file, unsigned initial_size)
{
  return filesys_create (file, initial_size);
}

bool remove (const char *file)
{
  /* File is removed regardless of whether it is open or closed. */
  return filesys_remove (file);
}

int open (const char *file)
{
  struct file *f;
  f = filesys_open (file);
  return fdt_insert (f);
}

int filesize (int fd)
{
  struct thread *cur = thread_current ();
  if (fd == 0 || fd == 1)
    return -1;
  if (cur->fdt[fd] == NULL)
    return -1;
  return file_length (cur->fdt[fd]);
}

int read (int fd, void* buffer, unsigned size)
{
  struct thread *cur;

  if (fd == 1)
    return -1;

  if (fd == 0)
    return input_getc();

  cur = thread_current ();
  if (cur->fdt[fd] == NULL)
    return -1;

  return file_read (cur->fdt[fd], buffer, size);
}

int write (int fd, const void *buffer, unsigned size)
{
  struct thread *cur;

  if (fd == 0)
    return -1;

  if (fd == 1)
  {
    putbuf (buffer, size);
    return size;
  }

  cur = thread_current ();
  if (cur->fdt[fd] == NULL)
    return -1;

  return file_write (cur->fdt[fd], buffer, size);
}

void seek (int fd, unsigned position)
{
  struct thread *cur = thread_current ();

  if (fd == 0 || fd == 1)
    return ;

  if (cur->fdt[fd] == NULL)
    return;

  file_seek (cur->fdt[fd], position);
}

unsigned tell (int fd)
{
  struct thread *cur = thread_current ();

  /*
  if (fd == 0 || fd == 1)
    return 0;

  if (cur->fdt[fd] == NULL)
    return 0;
  */

  return file_tell (cur->fdt[fd]);
}

void close (int fd)
{
  fdt_remove (fd);
}


static void check_user_pointer (const void* uaddr)
{
  if (uaddr == NULL)
    exit (FAILURE);
  if (!is_user_vaddr (uaddr))
    exit (FAILURE);
  if (uaddr < USER_VADDR_LOW_BOUND)
    exit (FAILURE);
}


static void copy_args (void* user_stack, int *args, int arg_num)
{
  int i;
  int *uaddr = NULL;

  for (i=0; i<arg_num; i++)
  {
    uaddr = (int*)user_stack;
    uaddr += (1 + i);
    check_user_pointer ((void*)uaddr);
    memcpy (args+i, uaddr, sizeof(int));
    // printf ("Copy arguments: %d\n", args[i]);
  }

}

static void copy_args_write (void* user_stack, int *args, int arg_num)
{
  int i;
  int *uaddr = NULL;

  for (i=0; i<arg_num; i++)
  {
    uaddr = (int*)user_stack;
    uaddr += (5 + i);
    check_user_pointer ((void*)uaddr);
    memcpy (args+i, uaddr, sizeof(int));
    // printf ("Copy arguments: %d\n", args[i]);
  }

}

static int
fdt_insert (struct file *f)
{
  struct thread* cur = thread_current ();
  int i;

  for (i = 2; i < FDT_SIZE; i++)
  {
    if (cur->fdt[i] == NULL)
    {
      cur->fdt[i] = f;
      return i;
    }
  }

  return -1;
}

static struct file *
fdt_find (int fd)
{
  return thread_current ()->fdt[fd];
}

static void
fdt_remove (int fd)
{
  struct thread *cur = thread_current ();
  /* if fd is 0 or 1? */
  
  /* close file */
  if (fd != 0 && fd != 1 && cur->fdt[fd] != NULL)
    file_close (cur->fdt[fd]);

  /* Resets FDT entry. */
  thread_current ()->fdt[fd] = NULL;
}
