/**
 * (C) 2007-20 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

#ifdef WIN32

#include "edge_utils_win32.h"

/* ************************************** */

static DWORD* tunReadThread(LPVOID lpArg) {
  struct tunread_arg *arg = (struct tunread_arg*)lpArg;

  while(*arg->keep_running)
	  edge_read_from_tap(arg->eee);

  return((DWORD*)NULL);
}

/* ************************************** */

/** Start a second thread in Windows because TUNTAP interfaces do not expose
 *  file descriptors. */
HANDLE startTunReadThread(struct tunread_arg *arg) {
  DWORD dwThreadId;

  return(CreateThread(NULL,         /* security attributes */
		      0,            /* use default stack size */
		      (LPTHREAD_START_ROUTINE)tunReadThread, /* thread function */
		      (void*)arg,   /* argument to thread function */
		      0,            /* thread creation flags */
		      &dwThreadId)); /* thread id out */
}
#endif

