#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/buffer-cache.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"

/* Partition that contains the file system. */
struct block *fs_device;

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

struct dir_entry
{
  block_sector_t inode_sector;
  char name[NAME_MAX +1];
  bool in_use;
};

// An open file.
//struct file 
//  {
//    struct inode *inode;        /* File's inode. */
//    off_t pos;                  /* Current position. */
//    bool deny_write;            /* Has file_deny_write() been called? */
//  };
//

static void do_format (void);
static struct dir *path_parser (char *path, bool *path_dir, bool *missing);
static struct dir *start_dir (char *path, int *jump);
static char *get_file_name (char *path);
static bool setup_dir (block_sector_t current, block_sector_t parent);


/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  /* Allocate the memory for buffer cache and handler and initialize it. */
  bc_init ();

  if (format) 
    do_format ();

  bc_destroy ();
  bc_init ();

  free_map_open ();
  
  /* Set root directory as current working directory. */
  thread_current ()->cur_dir = dir_open_root ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  bc_destroy ();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  block_sector_t inode_sector = 0;
  char *file_name = get_file_name (name);
  bool path_dir, missing;
  struct dir *dir = path_parser (name, &path_dir, &missing);

  /* File is already exists, but the file is directory. */
  if (!missing && path_dir)
    return false;

  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, false)
                  && dir_add (dir, file_name, inode_sector));
  if (!success && inode_sector != 0) 
  {
    free_map_release (inode_sector, 1);
  }
  dir_close (dir);
  free (file_name);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  char *file_name = get_file_name (name); // must deallocate.
  bool path_dir, missing;
  struct dir *dir = path_parser (name, &path_dir, &missing);
  struct inode *inode = NULL;

  if (dir == NULL)
    return NULL;

  if (missing)
  {
    dir_close (dir);
    free (file_name);
    return NULL;
  }

  /* File to be opened is a directory. */
  if (path_dir)
  {
    inode = dir_get_inode (dir);
    free (dir);
    return file_open (inode);
  }
  else
  {
    if (!dir_lookup (dir, file_name, &inode))
    {
      dir_close (dir);
      free (file_name);
      return NULL;
    }
  }

  dir_close (dir);
  free (file_name);  //

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char *file_name = get_file_name (name); // must deallocate.
  bool path_dir, missing;
  struct dir *dir = path_parser (name, &path_dir, &missing);
  struct dir *parent = NULL;
  struct inode *inode = NULL;
  bool success = false;
  enum intr_level old_level;

  if (dir == NULL)
  {
    dir_close (dir);
    if (file_name == NULL)
      free (file_name);
    return success;
  }

  /* File to be removed is directory.
     Check whether the directory is empty. */
  if (path_dir == true)
  {
    if (dir_is_empty (dir_get_inode (dir)))
    {
      if (!dir_lookup (dir, "..", &inode))
      {
        success = false;
      }
      else
      {
        parent = dir_open (inode);

        /* Directory to be removed is the current working directory. */
        old_level = intr_disable ();
        if (inode_get_inumber (dir_get_inode (dir))
            == inode_get_inumber (dir_get_inode (thread_current ()->cur_dir)))
        {
          thread_current ()->cur_dir = NULL;
          thread_current ()->parent_dir = parent;
        }
        intr_set_level (old_level);

        dir_close (dir);
        dir = parent;
        success = dir_remove (dir, file_name);
      }
    }
    else
    {
      success = false;
    }
  }
  else // just file -> remove it from the directory.
  {
    success = dir_remove (dir, file_name);
  }

  dir_close (dir);
  free (file_name);

  return success;
}

bool
filesys_chdir (const char *dir)
{
  struct thread *cur = thread_current ();
  bool path_dir, missing;
  struct directory *directory = NULL;
  // struct inode *inode = NULL;
  // char *dir_name = NULL;
  enum intr_level old_level;

  directory = path_parser (dir, &path_dir, &missing);
  // dir_name = get_file_name (dir); // must deallocate.
  if (directory == NULL)
    return false;

  if (missing)
    return false;

  // printf ("filesys_chdir (): directory_name {%s}\n", dir_name);

  old_level = intr_disable ();

  /*
  if (!dir_lookup (directory, dir_name, &inode))
  {
    dir_close (directory);
    // free (dir_name);

    printf ("filesys_chdir (): no such directory\n");
    return false;
  }

  if (!inode_is_dir (inode))
  {
    dir_close (directory);
    // free (dir_name);
 
    printf ("filesys_chdir (): not a directory\n");
    return false;
  }
  */

  // dir_close (directory);
  dir_close (cur->cur_dir);
  // cur->cur_dir = dir_open (inode);
  cur->cur_dir = directory;  

  intr_set_level (old_level);

  // free (dir_name);
  
  return true;
}

bool
filesys_mkdir (const char *dir)
{
  block_sector_t inode_sector = 0;
  bool path_dir, missing;
  char *file_name = get_file_name (dir);
  struct dir *parent = path_parser (dir, &path_dir, &missing);

  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  //&& inode_create (inode_sector, 
                  //                 16 * sizeof (struct dir_entry), true)
                  && dir_create (inode_sector, 16)
                  && dir_add (parent, file_name, inode_sector));
  if (!success && inode_sector != 0) 
  {
    free_map_release (inode_sector, 1);
  }

  /* Insert directory entries which represent the current directory,
     and the parent directory. */
  if (!setup_dir (inode_sector, inode_get_inumber (dir_get_inode (parent))))
  {
    free_map_release (inode_sector, 1);
    success = false;
  }
  
  // dir_close (dir);

  free (file_name);

  return success;
}

bool
filesys_readdir (int fd, char *name)
{
  /* Read FD. */
  struct file *file;
  struct dir *dir;
  char name_[NAME_MAX + 1];
  bool success = false;
	enum intr_level old_level = intr_disable ();

  file = thread_current ()->fdt[fd];
	intr_set_level (old_level);
  
  /* Check whether the fd is a directory or a file. */
  if (! inode_is_dir (file->inode))
    return success;

  dir = dir_open (file->inode);
  if (dir == NULL)
    return success;

  dir->pos = file->pos;

  while (!success)
  {
    success = dir_readdir (dir, name_);
    file->pos = dir->pos;
    if (!success) // no more entires.
      break;
    if (strcmp (name_, ".") == 0 || strcmp (name_, "..") == 0)
      success = false;
  }

  if (success)
    strlcpy (name, name_, strlen (name_) + 1);

  return success;
}

int
filesys_inumber (int fd)
{
  struct thread *cur = thread_current ();
  struct file *file = cur->fdt[fd];
  
  return inode_get_inumber ((const struct inode *) file->inode);
}


/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();

  /* Add directory entries '.' and '..' which represents
     the current directory and the parent directory. */
  setup_dir (ROOT_DIR_SECTOR, ROOT_DIR_SECTOR);

  printf ("done.\n");
}

/* Examine the given PATH, and parse the PATH
   to access to the associating directory.
   Return directory associated with path.
   The caller must close received directory. */
static struct dir *
path_parser (char *path, bool *path_dir, bool *missing)
{
  char *token, *save_ptr = NULL;
  struct dir *cur = NULL;
  struct inode *inode = NULL;
  int jump;

  if (path == NULL)
    return NULL;
  if (strlen (path) == 0)
    return NULL;

  char path_[strlen (path) + 1];
  strlcpy (path_, path, strlen (path) + 1);

  /* Starting directory. (root/current/parent directory) */
  cur = start_dir (path, &jump);

  /* Current directory is the root,
     but the requested path is the parent directory. */
  if (cur == NULL)
    return NULL;

  *missing = false;

  if (strlen (path) == jump)
    return cur;

  for (token = strtok_r (path_ + jump, "/", &save_ptr); token != NULL;
       token = strtok_r (NULL, "/", &save_ptr))
  {
    /* If there's no matching directory, return NULL. */
    if (!dir_lookup (cur, token, &inode))
    {
      if (strtok_r (NULL, "/", &save_ptr) == NULL)
      {
        *missing = true;
        break;
      }
      else
      {
        if (cur != NULL)
          dir_close (cur);
        return NULL;
      }
    }

    if (inode_is_dir (inode))
    {
      dir_close (cur);
      cur = dir_open (inode);
      *path_dir = true;
    }
    else
    {
      inode_close (inode);
      *path_dir = false;
      break; // newly append.
    }
  }

  return cur;
}

/* The caller must close received directory. */
static struct dir *
start_dir (char *path, int *jump)
{
  struct dir *cur = NULL;
  struct inode *inode = NULL;
  char name[] = "..";
  char path_[strlen (path) + 1];
  char *token, *save_ptr;

  strlcpy (path_, path, strlen (path) + 1);

  /* Distinguish whether the PATH is absolute path or relative path. */
  /* Absolute path starts with '/'. 
     If the current directory is NULL, dir should be root directory. */
  if (path[0] == '/' ||
      (thread_current ()->cur_dir == NULL
       && thread_current ()->parent_dir == NULL))
  {
    cur = dir_open_root ();
    *jump = 0;
  }
  /* Relative path starts with './'(from the current directory). */
  else if (path[0] == '.' && path[1] == '/')
  {
    cur = dir_reopen (thread_current ()->cur_dir);
    token = strtok_r (path_, "/", &save_ptr);
    *jump = strlen (token) + 1;
  }
  /* Relative path starts with '../'(from the parent directory) */
  else if (path[0] == '.' && path[1] == '.' && path[2] == '/')
  {
    cur = dir_reopen (thread_current ()->cur_dir);

    /* If the current directory is the root directory. */
    if (inode_get_inumber (dir_get_inode (cur)) == ROOT_DIR_SECTOR)
      return NULL;

    if (!dir_lookup (cur, name, &inode))
    {
      free (inode);
      return NULL;
    }

    dir_close (cur);
    cur = dir_open (inode);

    free (inode);
    
    token = strtok_r (path_, "/", &save_ptr);
    *jump = strlen (token) + 1;
  }
  else if (path[0] == '.')
  {
    cur = dir_reopen (thread_current ()->cur_dir);
    *jump = 1;
  }
  else// not start with '/'
  {
    /* If the working directory is removed. */
    if (thread_current ()->cur_dir == NULL
        && thread_current ()->parent_dir != NULL)
    {
      return NULL;
    }
    cur = dir_reopen (thread_current ()->cur_dir);
    *jump = 0;
  }

  return cur;
}

/* The call must deallocate the received string literal. */
static char *
get_file_name (char *path)
{
  char *token, *save_ptr, *file_name_, *file_name = NULL;
  char path_[strlen (path) + 1];
  int jump = 0;
  strlcpy (path_, path, strlen (path) + 1);

  /* Distinguish whether the PATH is absolute path or relative path. */
  /* Absolute path starts with '/'. 
     If the current directory is NULL, dir should be root directory. */
  if (path[0] == '/' ||
      (thread_current ()->cur_dir == NULL
       && thread_current ()->parent_dir == NULL))
  {
    jump = 0;
  }
  /* Relative path starts with './'(from the current directory). */
  else if (path[0] == '.' && path[1] == '/')
  {
    token = strtok_r (path_, "/", &save_ptr);
    jump = strlen (token) + 1;
  }
  /* Relative path starts with '../'(from the parent directory) */
  else if (path[0] == '.' && path[1] == '.' && path[2] == '/')
  {  
    token = strtok_r (path_, "/", &save_ptr);
    jump = strlen (token) + 1;
  }
  else // not start with '/'
  {
    /* If the working directory is removed. */
    if (thread_current ()->cur_dir == NULL
        && thread_current ()->parent_dir != NULL)
    {
      return NULL;
    }
    jump = 0;
  }

  strlcpy (path_, path, strlen (path) + 1);

  for (token = strtok_r (path_ + jump, "/", &save_ptr); token != NULL;
       token = strtok_r (NULL, "/", &save_ptr))
  {
    file_name_ = token;
  }
  
  file_name = malloc (strlen (file_name_) + 1);
  strlcpy (file_name, file_name_, strlen (file_name_) + 1);

  return file_name;
}

static bool
setup_dir (block_sector_t current, block_sector_t parent)
{
  struct inode *inode = inode_open (current);
  struct dir *cur = dir_open (inode);
  bool success = true;

  /* Add directory entries which represent
     the current directory, and the parent directory. */
  if (!dir_add (cur, ".", current) || !dir_add (cur, "..", parent))
    success = false;

  inode_close (inode);
  dir_close (cur);

  return success;
}

