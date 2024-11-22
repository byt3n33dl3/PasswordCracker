/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2013 by Solar Designer
 */

/*
 * John's global variables exported from john.c to other source files.
 */

#ifndef _JOHN_JOHN_H
#define _JOHN_JOHN_H

#include "loader.h"

/*
 * Are we the main process?  (The only process or the parent of a group of
 * child processes.)
 */
extern int john_main_process;

#ifndef NEED_OS_FORK
#define NEED_OS_FORK
#include "os.h"
#endif

#if OS_FORK
/*
 * Number of child processes, if any (or zero otherwise).
 */
extern int john_child_count;

/*
 * Child process PIDs array, element 0 corresponds to node 2, array size is
 * john_child_count elements.  (This is only used when options.fork is set,
 * otherwise the pointer is NULL.)
 */
extern int *john_child_pids;
#endif

/* Terminal locale is read in john_init() and copied to this variable */
extern char *john_terminal_locale;

/* Current target for options.max_cands */
extern uint64_t john_max_cands;

/* Print loaded/remaining counts */
extern char *john_loaded_counts(struct db_main *db, char *prelude);

#endif
