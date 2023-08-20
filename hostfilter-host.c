/* Copyright (C) 2000, 2001 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Mark Kettenis <kettenis@gnu.org>, 2000.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include <stddef.h>
#include <errno.h>
#include <netdb.h>
#include <nss.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>

/* Allow the resolution of the hostname by other plugins */
static enum nss_status allow(struct hostent *result, int *errnop, int *herrnop)
{
   result = NULL;
   *errnop = ENOENT;
   *herrnop = HOST_NOT_FOUND;
   return NSS_STATUS_NOTFOUND;
}

static char* alloc_space_on_buffer(
   size_t size, char** buffer_ptr, size_t* buflen_ptr
) {
   if (size > *buflen_ptr) return NULL;
   
   char* buffer = *buffer_ptr;
   *buffer_ptr += size;
   *buflen_ptr -= size;
   return buffer;
}

static enum nss_status tryagain(
   struct hostent *result, int *errnop, int *herrnop
) {
      result = NULL;
      *errnop = ERANGE;
      *herrnop = TRY_AGAIN;
      return NSS_STATUS_TRYAGAIN;
}

/* Prevent the resolution of the hostname by other plugins by returning a dummy
   IP address */
static enum nss_status deny(
   const char* name, int af, struct hostent *result, char *buffer,
   size_t buflen, int* errnop, int *herrnop
) {
   static const char *dummy_address = "192.168.2.254";
      /* Use a local address that is not routable, or a 'landing' host. */

   if (af != AF_INET) {
      result = NULL;
      *herrnop = NO_DATA;
      *errnop = NO_ADDRESS;
      return NSS_STATUS_NOTFOUND;
      /* Maybe we should return a dummy IPv6 address here instead. */
   }
   /* Every pointer of hostent must point into buffer. Its lifecycle is managed
      by the caller. However only buffer is freed by caller not any pointers in
      hostent, so a pointer to static const char array can be returned, too. */
   
   if (!
      (
	 result->h_name = (
	    alloc_space_on_buffer(strlen(name) + 1, &buffer, &buflen)
	 )
      )
   ) return tryagain(result, errnop, herrnop);
   strcpy(result->h_name, name);
   
   if (!
      (
	 result->h_aliases = (char**)(
	    alloc_space_on_buffer(sizeof(char*), &buffer, &buflen)
	 )
      )
   ) return tryagain(result, errnop, herrnop);
   result->h_aliases[0] = NULL;
   
   result->h_addrtype = AF_INET; 
   
   /* "network address" is struct in_addr (IPv4). (char ** is coming from
      ancient times when void ** was not available in C.) */
   result->h_length = sizeof(struct in_addr); 

   if (!
      (
	 result->h_addr_list = (char**)(
	    alloc_space_on_buffer(2 * sizeof(char*), &buffer, &buflen)
	 )
      )
   ) return tryagain(result, errnop, herrnop);
   if (!
      (
	 result->h_addr_list[0] = (
	    alloc_space_on_buffer(result->h_length, &buffer, &buflen)
	 )
      )
   ) return tryagain(result, errnop, herrnop);
   inet_aton(dummy_address, (struct in_addr*)(result->h_addr_list[0]));
   result->h_addr_list[1] = NULL;
   
   *errnop = NETDB_SUCCESS;
   return NSS_STATUS_SUCCESS;
}

static enum nss_status
internal_getipnodebyname_r(const char *name, int af, 
			    struct hostent *result, char *buffer,
			    size_t buflen, int *errnop, int *herrnop)
{
   static const char is_host_allowed_command[] = "./is_host_allowed.sh";
   char *is_host_allowed_commandline;
   if (
      !(
	 is_host_allowed_commandline = (
	    malloc(sizeof(is_host_allowed_command) + strlen(name) + 3)
	 )
      )
   ) {
      error(0, 0, "nss-hostfilter: Internal error.");
      return allow(result, errnop, herrnop);
   }
   *is_host_allowed_commandline = 0;
   strcat(
      strcat(
	 strcat(
	    strcat(is_host_allowed_commandline, is_host_allowed_command), " \""
	 ), name
      ), "\""
   );
   int rc = system(is_host_allowed_commandline);
   free(is_host_allowed_commandline);
   if (rc != -1 && WIFEXITED(rc) && WEXITSTATUS(rc) != 127) {
      return (
	 WEXITSTATUS(rc) == 0 ?
	    allow(result, errnop, herrnop) :
	    deny(name, af, result, buffer, buflen, errnop, herrnop)
      );
   }
   error(
      0, 0, "nss-hostfilter: Error executing the external command. (%d)", rc
   );
   return allow(result, errnop, herrnop);
}

enum nss_status
_nss_hostfilter_gethostbyname2_r (const char *name, int af, struct hostent *result,
			     char *buffer, size_t buflen, int *errnop,
			     int *herrnop)
{
  return internal_getipnodebyname_r (name, af, result, buffer, buflen,
				     errnop, herrnop);
}

enum nss_status
_nss_hostfilter_gethostbyname_r (const char *name, struct hostent *result,
			  char *buffer, size_t buflen, int *errnop,
			  int *herrnop)
{
  return internal_getipnodebyname_r (name, AF_INET, result,
				     buffer, buflen, errnop, herrnop);
}