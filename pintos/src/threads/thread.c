#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of processes in waiting for timer expiration */
static struct list sleep_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

static int64_t min_tick_sleeplist = 0;  /* The minimum tick in the sleep list. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&sleep_list);
  list_init (&all_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level (old_level);

  /* Add to run queue. */
  thread_unblock (t);

  /* If the newly arriving thread has higher priority 
   * than the current thread, Yield the CPU. */
  if (priority > thread_get_priority ())
    thread_yield ();

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  list_insert_ordered (&ready_list, &t->elem, cmp_priority_elem, NULL);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) 
    list_insert_ordered (&ready_list, &cur->elem, cmp_priority_elem, NULL);
  cur->status = THREAD_READY;

  schedule ();
  intr_set_level (old_level);
}

/* Priority Preemption
 * If the priority of the current thread is less than
 * that of the thread in the ready list, the current thread gives the control up. */
void
thread_preemption (void)
{
  struct thread *cur = thread_current ();
  struct thread *ready = NULL;
  struct list_elem *e = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (!intr_context ());

  if (!list_empty (&ready_list))
  {
    e = list_front (&ready_list);
    ready = list_entry (e, struct thread, elem);
    if (cur->priority < ready->priority)
    {
      thread_yield ();
    }
  }
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

void
thread_donate_priority (void)
{
  struct lock *lock = thread_current ()->wait_on_lock;
  struct thread *lock_holder = lock->holder;
  struct thread *t = NULL;
  struct list_elem *e = NULL;

  ASSERT (!intr_context ());
  ASSERT (is_thread (lock_holder));
  ASSERT (!lock_held_by_current_thread (lock));
  ASSERT (intr_get_level () == INTR_OFF);

  /* From the donation list of the donation receiving thread,
       * removes the donated thread which waits for the same lock if exists
       * , because it has smaller priority than the curren thread. */ 
  for (e = list_begin (&lock_holder->donations);
       e != list_end (&lock_holder->donations); e = list_next (e))
  {
    t = list_entry (e, struct thread, donated_elem);
    if (t->wait_on_lock == lock)
    {
      list_remove (e);
      break;
      /* Because this "break" operation
       * , there's only one thread waiting for the same lock
       * , so we don't need to traverse further. */
    }
  }

  /* Puts the current thread's D_ELEM in the donation list. */
  list_insert_ordered (&lock_holder->donations,
                       &thread_current ()->donated_elem,
                       cmp_priority_donated_elem, NULL);

  /* Priority Donation */
  thread_set_priority_donation (lock_holder);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  struct thread *cur = thread_current ();
  struct thread *donator = NULL;
  struct list_elem *e = NULL;
  struct list_elem *d = NULL;
  enum intr_level old_level;

  ASSERT (PRI_MIN <= new_priority && new_priority <= PRI_MAX);

  old_level = intr_disable ();
  
  cur->priority = new_priority;
  
  if (!list_empty (&cur->donations))
  {
    e = list_rbegin (&cur->donations);
    while (e != list_rend (&cur->donations))
    {
      donator = list_entry (e, struct thread, donated_elem);
      if (donator->priority <= new_priority)
      {
        d = e;
        e = list_prev (e);
        list_remove(d);
      }
      else
        break;
    }
    thread_set_priority_if_donated ();
  }

  thread_preemption ();
  intr_set_level (old_level);
 
}

/* Restore the current thread's original priority, not donated one. */
void
thread_set_priority_properly (void)
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;

  old_level = intr_disable ();

  if (cur->priority_mine != -1)
  {
    cur->priority = cur->priority_mine;
    cur->priority_mine = -1;
  }
  thread_set_priority_if_donated ();

  intr_set_level (old_level);
}

/* Checks whether the current thread received priority donations
 * from the other higher-priority threads or not,
 * then if yes, set the priority of the current thread to 
 * the priority of the hightest donated thread. */
void
thread_set_priority_if_donated (void)
{
  struct thread* donator = NULL;
  struct thread* cur = thread_current ();

  ASSERT (intr_get_level () == INTR_OFF);

  if (!list_empty (&cur->donations))
  {
    cur->priority_mine = cur->priority;
    donator = list_entry (list_begin (&cur->donations),
                          struct thread, donated_elem);
    cur->priority = donator->priority;
  }
}

/* Set the donation received thread's priority 
 * to the donated priority.
 * Therefore, this function should be called only
 * when donation should be occured in the function LOCK_ACQUIRE. */
void
thread_set_priority_donation (struct thread* receiver)
{
  int new_priority;
  struct thread* donator = NULL;
  
  ASSERT (is_thread (receiver));
  ASSERT (!list_empty (&receiver->donations));
  ASSERT (intr_get_level () == INTR_OFF);

  donator = list_entry (list_begin (&receiver->donations),
                        struct thread, donated_elem);
  new_priority = donator->priority;

  if (receiver->priority_mine == -1)
    receiver->priority_mine = receiver->priority;
  receiver->priority = new_priority;

  /* nested donation */
  if (receiver->wait_on_lock != NULL && receiver->wait_on_lock->holder != NULL) 
    thread_set_priority_nested_donation (receiver, 
                                         &donator->donated_elem, new_priority);

}

void
thread_set_priority_nested_donation (struct thread* receiver,
                                     struct list_elem* donated_elem, int new_priority)
{
  struct thread* lock_holder = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (is_thread (receiver));
  ASSERT (donated_elem != NULL);
  ASSERT (receiver->wait_on_lock != NULL && receiver->wait_on_lock->holder != NULL);
  ASSERT (PRI_MIN <= new_priority && new_priority <= PRI_MAX);

  lock_holder = receiver->wait_on_lock->holder;
  if (lock_holder->priority < new_priority)
  {
    /* There can be a situation which the lock holder thread
     * already received donation, and the donated priority is less than 
     * the current new priority. */
    if (lock_holder->priority_mine == -1)
      lock_holder->priority_mine = lock_holder->priority;
    lock_holder->priority = new_priority;
    /* list_insert_ordered (&lock_holder->donations, donated_elem,
                         cmp_priority_donated_elem, NULL); */

    if (lock_holder->wait_on_lock != NULL &&
        lock_holder->wait_on_lock->holder != NULL)
      thread_set_priority_nested_donation (lock_holder, donated_elem, new_priority);
  }
  /* If the lock holder has higher priority than the waiting thread,
   * the waiting thread should not donate its relatively low priority. */
}

/* Sets the current thread's */
void
thread_set_wait_on_lock (struct lock* lock)
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;

  ASSERT (lock !=NULL);

  old_level = intr_disable ();
  cur->wait_on_lock = lock;
  intr_set_level (old_level);
}

void
thread_clear_wait_on_lock (void)
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;

  old_level = intr_disable ();
  cur->wait_on_lock = NULL;
  intr_set_level (old_level);
}

int
thread_clean_donation_list (struct lock *lock)
{
  struct thread *cur = thread_current ();
  struct thread *t = NULL;
  struct thread *dt = NULL; /* highest donator */
  struct list_elem *e = NULL;
  struct list_elem *de = NULL; /* highest donator's DONATED_ELEM */
  struct list *donation_list = NULL;

  ASSERT (lock != NULL);
  ASSERT (lock_held_by_current_thread (lock));
  ASSERT (intr_get_level () == INTR_OFF);
  
  donation_list = &cur->donations;
  if (!list_empty (donation_list))
  {
    for (e = list_begin (donation_list); e != list_end (donation_list);
         e = list_next (e))
    {
      t = list_entry (e, struct thread, donated_elem);
      if (t->wait_on_lock == lock)
      {
        list_remove (e);

        /* There can be a nested donator */
        if (t->priority != cur->priority)
        {
          de = list_begin (donation_list);
          dt = list_entry (de, struct thread, donated_elem);
          
          if (dt->priority != cur->priority)
            return 1; /* nested donation */
        }
        return 0;
        /* Breaks because donator could donate only
         * when it has the higher prioirty than other
         * , and also the lower one are kicked out when higher one comes in. */
      }
    }
  
  }
  return 0;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) 
{
  /* Not yet implemented. */
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  /* Not yet implemented. */
  return 0;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  /* Not yet implemented. */
  return 0;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  /* Not yet implemented. */
  return 0;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->magic = THREAD_MAGIC;
  list_push_back (&all_list, &t->allelem);
  t->wakeup_tick = 0;
  t->priority_mine = -1; /* -1 means t->priority is mine. */
  t->wait_on_lock = NULL;
  list_init (&t->donations);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

/* Change the state of the caller thread to 'BLOCKED' and
 * put it to the sleep queue 'sleep_list' */
void
thread_sleep(int64_t ticks)
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;

  ASSERT (!intr_context ());
  ASSERT (ticks>0);

  old_level = intr_disable ();
  if (cur != idle_thread)
  {
    cur->status = THREAD_BLOCKED;
    cur->wakeup_tick = ticks;

		/* Resets the minimum tick value in sleep queue
			* if it's minimum tick */
    if (ticks < min_tick_sleeplist)
      min_tick_sleeplist = ticks;

    list_insert_ordered (&sleep_list, &cur->elem, cmp_tick, NULL);
  }
  schedule ();
  intr_set_level (old_level);
}

/* Finds all threads to wake up, and awakes it/them. */
void
thread_awake (int64_t ticks)
{
  struct list_elem* e = NULL;
  struct list_elem* d = NULL;
  struct thread* t = NULL;
  enum intr_level old_level;

  ASSERT (intr_get_level () == INTR_OFF);

  if (!list_empty (&sleep_list))
  {
    old_level = intr_disable ();

    e = list_begin (&sleep_list);
    
    while ( e != list_end (&sleep_list) )
    {
      t = list_entry (e, struct thread, elem);
      if (t->wakeup_tick <= ticks)
        {
          d = e;
          e = list_next(e);
          list_remove (d);
          t->status = THREAD_READY;
          list_insert_ordered (&ready_list, &t->elem,
                             cmp_priority_elem, NULL);
        }
      else
        break; /* because sleep list is sorted */
      }
    intr_set_level (old_level);
  }
}

/* Returns the minimum tick in the sleep queue.
 * Minimum tick value "min_tick_sleep" is static global. */
int64_t
get_min_tick_sleeplist (void)
{
  ASSERT (intr_get_level () == INTR_OFF);

  return min_tick_sleeplist;
}

/* Updates the minimum tick in the sleep queue. */
int64_t
update_min_tick_sleeplist (void)
{
  struct list_elem* min_e = NULL;
  struct thread* min_t = NULL;

  ASSERT (intr_get_level () == INTR_OFF);

  /* sleep list is sorted by expired time
   * in non-increasing order */
  min_e = list_begin (&sleep_list);
  min_t = list_entry (min_e, struct thread, elem);

  min_tick_sleeplist = min_t->wakeup_tick;

  return min_tick_sleeplist;
}

/* Compares the local tick values of two LIST_ELEM in sleep queue.
 * Returns true if the tick value of A is less than that of B,
 * return false oterwise. */
bool
cmp_tick (const struct list_elem *a, const struct list_elem *b,
          void* aux UNUSED)
{
  struct thread* x = list_entry (a, struct thread, elem);
  struct thread* y = list_entry (b, struct thread, elem);
  if (x->wakeup_tick < y->wakeup_tick)
    return true;
  else
    return false;
}

/* Compares the values of the priority of two LIST_ELEM in READY_LIST.
 * Return true if the priority of A is greater than or equal to that of B
 * , otherwise return false. */
bool
cmp_priority_elem (const struct list_elem *a,
                   const struct list_elem *b, void* aux UNUSED)
{
    struct thread* x = list_entry (a, struct thread, elem);
    struct thread* y = list_entry (b, struct thread, elem);
    if (x->priority > y->priority)
        return true;
    else
        return false;
}

/* Compares the values of the priority of two D_ELEM in donation list.
 * Return true if the priority of A is greater than or equal to that of B
 * , otherwise return false. */
bool
cmp_priority_donated_elem (const struct list_elem *a,
                           const struct list_elem *b, void* aux UNUSED)
{
    struct thread* x = list_entry (a, struct thread, donated_elem);
    struct thread* y = list_entry (b, struct thread, donated_elem);
    if (x->priority >= y->priority)
        return true;
    else
        return false;
}
