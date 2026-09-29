/* SPDX-License-Identifier: BSD-2-Clause */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "elfhack/misc.h"

bool
is_plain_integer(const char *str)
{
   if (!*str)
      return false; /* not even a single digit */

   for (const char *p = str; *p != '\0'; p++) {
      if (!isdigit((unsigned char)*p))
         return false;
   }

   return true;
}

bool
is_index_string(const char *str)
{
   if (*str != '#')
      return false;

   if (!isdigit(*(str + 1)))
      return false; /* not even a single digit after '#' */

   return is_plain_integer(str + 1);
}

void
die_with_invalid_index_error(const char *str)
{
   fprintf(stderr, "ERROR: invalid index '%s'\n", str);
   exit(1);
}

static int
write_all(int fd, const char *buf, size_t size)
{
   size_t written = 0;
   ssize_t count;

   while (written < size) {

      count = write(fd, buf + written, size - written);

      if (count < 0) {

         if (errno == EINTR)
            continue;

         return -1;
      }

      written += (size_t)count;
   }

   return 0;
}

static int
copy_fd_contents(int src_fd, int dest_fd)
{
   char buf[4096];
   ssize_t count;

   while (true) {

      count = read(src_fd, buf, sizeof(buf));

      if (count < 0) {

         if (errno == EINTR)
            continue;

         return -1;
      }

      if (count == 0)
         return 0; /* EOF */

      if (write_all(dest_fd, buf, (size_t)count) < 0)
         return -1;
   }
}

/*
 * Create a new temporary file in the same directory as `dest` (so that it can
 * later be renamed over it atomically) and fill it with `src_fd`'s contents
 * and `mode`. Returns the path of the temporary file, or NULL on failure.
 */
static char *
create_temp_copy(int src_fd, mode_t mode, const char *src, const char *dest)
{
   static const char suffix[] = ".XXXXXX";
   char *tmp_path;
   int tmp_fd;
   int err = 0;

   tmp_path = malloc(strlen(dest) + sizeof(suffix));

   if (!tmp_path) {
      fprintf(stderr, "ERROR: out of memory\n");
      return NULL;
   }

   strcpy(tmp_path, dest);
   strcat(tmp_path, suffix);
   tmp_fd = mkstemp(tmp_path);

   if (tmp_fd < 0) {
      fprintf(stderr, "ERROR: cannot create a temporary file for %s: %s\n",
              dest, strerror(errno));
      free(tmp_path);
      return NULL;
   }

   if (fchmod(tmp_fd, mode & 07777) < 0)
      err = errno;
   else if (copy_fd_contents(src_fd, tmp_fd) < 0)
      err = errno;

   /* close() can report a deferred write error: check it too */
   if (close(tmp_fd) < 0 && !err)
      err = errno;

   if (err) {
      fprintf(stderr, "ERROR: cannot copy %s to %s: %s\n",
              src, tmp_path, strerror(err));
      unlink(tmp_path);
      free(tmp_path);
      return NULL;
   }

   return tmp_path;
}

char *
file_copy_to_temp(const char *src, const char *dest)
{
   struct stat statbuf;
   char *tmp_path = NULL;
   int src_fd;

   src_fd = open(src, O_RDONLY);

   if (src_fd < 0) {
      fprintf(stderr, "ERROR: cannot open %s for reading: %s\n",
              src, strerror(errno));
      return NULL;
   }

   if (fstat(src_fd, &statbuf) < 0) {
      fprintf(stderr, "ERROR: cannot stat %s: %s\n", src, strerror(errno));
      goto out;
   }

   if (!S_ISREG(statbuf.st_mode)) {
      fprintf(stderr, "ERROR: %s is not a regular file\n", src);
      goto out;
   }

   tmp_path = create_temp_copy(src_fd, statbuf.st_mode, src, dest);

out:
   close(src_fd);
   return tmp_path;
}

int
file_commit_temp(const char *tmp_path, const char *dest, int rc)
{
   if (rc) {
      unlink(tmp_path);
      return rc;
   }

   if (rename(tmp_path, dest) < 0) {
      fprintf(stderr, "ERROR: cannot rename %s to %s: %s\n",
              tmp_path, dest, strerror(errno));
      unlink(tmp_path);
      return 1;
   }

   return 0;
}

