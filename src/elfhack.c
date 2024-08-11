/* SPDX-License-Identifier: BSD-2-Clause */

/*
 * A tool for hacking ELF binaries.
 *
 * Imported from the Tilck project:
 * https://github.com/vvaltchev/tilck
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "basic_defs.h"
#include "elf_utils.h"
#include "cmds.h"

typedef int (*cmd_func_0)(struct elf_file_info *);

typedef int (*cmd_func_1)(struct elf_file_info *,
                          const char *);

typedef int (*cmd_func_2)(struct elf_file_info *,
                          const char *,
                          const char *);

typedef int (*cmd_func_3)(struct elf_file_info *,
                          const char *,
                          const char *,
                          const char *);


struct elfhack_option *options_head;
struct elfhack_option *options_tail;

void register_option(struct elfhack_option *cmd)
{
   if (!options_tail) {

      assert(!options_head);
      options_head = cmd;
      options_tail = cmd;

   } else {

      options_tail->next = cmd;
      options_tail = cmd;
   }
}

int
show_help(struct elf_file_info *nfo)
{
   UNUSED_VARIABLE(nfo);
   fprintf(stderr, "Usage:\n");

   struct elfhack_option *c = options_head;
   while (c) {
      fprintf(stderr, "    elfhack <file> %s %s\n", c->opt, c->help);
      c = c->next;
   }

   return 0;
}

REGISTER_CMD(
   help,
   "--help",
   "",
   0,
   &show_help
)


int
elf_header_type_check(struct elf_file_info *nfo)
{
   Elf32_Ehdr *h = nfo->vaddr;

   if (h->e_ident[EI_MAG0] != ELFMAG0 ||
       h->e_ident[EI_MAG1] != ELFMAG1 ||
       h->e_ident[EI_MAG2] != ELFMAG2 ||
       h->e_ident[EI_MAG3] != ELFMAG3)
   {
      fprintf(stderr, "Not a valid ELF binary (magic doesn't match)\n");
      return 1;
   }

   if (sizeof(Elf_Addr) == 4) {

      if (h->e_ident[EI_CLASS] != ELFCLASS32) {
         fprintf(stderr, "ERROR: expected 32-bit binary\n");
         return 1;
      }

   } else {

      if (h->e_ident[EI_CLASS] != ELFCLASS64) {
         fprintf(stderr, "ERROR: expected 64-bit binary\n");
         return 1;
      }
   }

   return 0;
}

struct elfhack_option *
find_cmd(const char *opt)
{
   struct elfhack_option *cmd = options_head;
   
   while (cmd) {

      if (!strcmp(opt, cmd->opt)) {
         return cmd;
      }

      cmd = cmd->next;
   }

   return NULL;
}

int
run_cmds(struct elf_file_info *nfo, int argc, char **argv)
{
   struct elfhack_option *cmd = NULL;
   const char *opt;
   int rc = 0;

   while (argc > 0 && argv[0]) {

      opt = argv[0];
      cmd = find_cmd(opt);
      argc--; argv++;

      if (!cmd) {

         cmd = options_head;    /* help */

      } else {

         if (argc < cmd->nargs) {
            fprintf(stderr, "ERROR: Invalid number of arguments for %s "
                    "(expected: %d, got: %d).\n", opt, cmd->nargs, argc);
            return 1;
         }
      }

      switch (cmd->nargs) {
         case 0:
            rc = ((cmd_func_0)cmd->func)(nfo);
            break;
         case 1:
            rc = ((cmd_func_1)cmd->func)(nfo, argv[0]);
            break;
         case 2:
            rc = ((cmd_func_2)cmd->func)(nfo, argv[0], argv[1]);
            break;
         case 3:
            rc = ((cmd_func_3)cmd->func)(nfo, argv[0], argv[1], argv[2]);
            break;
         default:
            abort();
      }

      argc += cmd->nargs;
      argv += cmd->nargs;
   }

   return rc;
}

int
main(int argc, char **argv)
{
   struct elf_file_info nfo = {0};
   struct stat statbuf;
   size_t page_size;
   int rc;

   if (argc <= 1 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
      show_help(NULL);
      return 1;
   }

   nfo.path = argv[1];
   nfo.fd = open(nfo.path, O_RDWR);

   if (nfo.fd < 0) {
      perror("open failed");
      return 1;
   }

   if (fstat(nfo.fd, &statbuf) < 0) {
      perror("fstat failed");
      close(nfo.fd);
      return 1;
   }

   page_size = sysconf(_SC_PAGESIZE);

   if (page_size <= 0) {
      fprintf(stderr, "Unable to get page size. Got: %ld\n", (long)page_size);
      close(nfo.fd);
      return 1;
   }

   nfo.mmap_size = pow2_round_up_at((size_t)statbuf.st_size, page_size);

   errno = 0;
   nfo.vaddr = mmap(NULL,                   /* addr */
                    nfo.mmap_size,          /* length */
                    PROT_READ | PROT_WRITE, /* prot */
                    MAP_SHARED,             /* flags */
                    nfo.fd,                 /* fd */
                    0);                     /* offset */

   if (errno) {
      perror(NULL);
      return 1;
   }

   if (elf_header_type_check(&nfo)) {
      rc = 1;
      goto end;
   }

   rc = run_cmds(&nfo, argc - 2, argv + 2);

end:
   if (munmap(nfo.vaddr, nfo.mmap_size) < 0) {
      perror("munmap() failed");
   }

   close(nfo.fd);
   return rc;
}
