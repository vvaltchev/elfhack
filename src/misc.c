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

bool
is_plain_integer(const char *str)
{
   for (const char *p = str; *p != '\0'; p++) {
      if (!isdigit(*p))
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
write_chunk_to_file(int fd, void *buf, ssize_t total_size)
{
   ssize_t count;
   ssize_t total_written = 0;

   while (total_written < total_size) {

      count = write(fd, buf + total_written, total_size - total_written);

      if (count <= 0) {

         if (errno == EINTR)
            continue;

         if (errno)
            fprintf(stderr, "Write error: %s\n", strerror(errno));

         break;
      }

      total_written += count;
   }

   return 0;
}

int
file_copy(const char *src, const char *dest)
{
   struct stat statbuf;
   int rc, source_fd, dest_fd;
   ssize_t read_count;
   ssize_t total_read;
   char buf[4096];

   printf("file copy %s -> %s\n", src, dest);

   rc = stat(src, &statbuf);
   if (rc < 0) {
      fprintf(stderr, "Cannot stat file %s: %s", src, strerror(errno));
      return 1;
   }

   if (!S_ISREG(statbuf.st_mode)) {
      fprintf(stderr, "%s is not a regular file\n", src);
      return 1;
   }

   source_fd = open(src, O_RDONLY);
   if (source_fd < 0) {
      fprintf(stderr,
              "Cannot open for reading file %s: %s\n",
              src, strerror(errno));
      return 1;
   }

   dest_fd = open(dest, statbuf.st_mode | O_CREAT | O_WRONLY);
   if (dest_fd < 0) {
      fprintf(stderr,
              "Cannot open file %s for writing: %s\n",
              dest, strerror(errno));
      return 1;
   }

   errno = 0;
   total_read = 0;

   while (total_read < statbuf.st_size) {

      read_count = read(source_fd, buf, sizeof(buf));

      if (read_count <= 0) {

         if (errno == EINTR)
            continue;

         if (errno)
            fprintf(stderr, "Read error: %s\n", strerror(errno));

         break;
      }

      total_read += read_count;
      rc = write_chunk_to_file(dest_fd, buf, read_count);

      if (rc)
         break; /* write error */
   }

   close(dest_fd);
   close(source_fd);
   return 0;
}


