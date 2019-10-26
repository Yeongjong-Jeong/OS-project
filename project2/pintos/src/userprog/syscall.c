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

#define USER_VADDR_LOW_BOUND ((void*) 0x08048000)
#define SUCCESS 0
#define FAILURE 1

static void syscall_handler (struct intr_frame *);
static void copy_args (void* user_stack, int *args, int arg_num);

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

  printf ("System call number: %d\n", system_call_number);
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
    
      break;
    }
    case SYS_CREATE:                 /* Create a file. */
    {
    
      break;
    }
    case SYS_REMOVE:                 /* Delete a file. */
    {
    
      break;
    }
    case SYS_OPEN:                   /* Open a file. */
    {
    
      break;
    }
    case SYS_FILESIZE:               /* Obtain a file's size. */
    {
      copy_args (f->esp, args, 3);
      write (args[0], (void*)args[1], (unsigned)args[2]);
      break;
    }
    case SYS_READ:                   /* Read from a file. */
    {
    
      break;
    }
    case SYS_WRITE:                  /* Write to a file. */
    {
    
      break;
    }
    case SYS_SEEK:                   /* Change position in a file. */
    {
    
      break;
    }
    case SYS_TELL:                   /* Report current position in a file. */
    {
    
      break;
    }
    case SYS_CLOSE:                  /* Close a file. */
    {
    
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
  return false;
}

bool remove (const char *file)
{
  return false;
}

int open (const char *file)
{
  return -1;
}

int filesize (int fd)
{
  return -1;
}


int read (int fd, void* buffer, unsigned size)
{
  return 0;

}

int write (int fd, const void *buffer, unsigned size)
{
  if (fd == 1)
  {
    putbuf (buffer, size);
    return size;
  }
  // else - file_write
  return -1;
}

void seek (int fd, unsigned position)
{
  return ;
}

unsigned tell (int fd)
{
  return 0;
}

void close (int fd)
{
  return ;
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
    printf ("Copy arguments: %d\n", args[i]);
  }

}
