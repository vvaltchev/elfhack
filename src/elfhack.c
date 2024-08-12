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

#include "elfhack/basic_defs.h"
#include "elfhack/elf_utils.h"
#include "elfhack/options.h"

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

static void
dump_options(enum elfhack_option_type type)
{
   struct elfhack_option *c;
   char buf[256];

   for (c = options_head; c != NULL; c = c->next) {

      if (c->type != type)
         continue;

      assert(c->long_opt);

      if (!c->short_opt) {
         sprintf(buf, "        %s", c->long_opt);

      } else {
         sprintf(buf, "    %-3s %s",
               c->short_opt, c->long_opt);
      }

      fprintf(stderr, "%-35s %s\n", buf, c->help);
   }
}

int
show_help(struct elf_file_info *nfo)
{
   UNUSED_VARIABLE(nfo);
   fprintf(stderr, "Usage:\n");
   fprintf(stderr, "    elfhack <file> "
                   "[--action [args...]]... [--modifier]...\n");

   fprintf(stderr, "\n");
   fprintf(stderr, "Actions:\n");
   dump_options(ELFHACK_ACTION);

   fprintf(stderr, "\n");
   fprintf(stderr, "Modifiers:\n");
   dump_options(ELFHACK_FLAG);
   dump_options(ELFHACK_ENUM);
   return 0;
}

REGISTER_CMD(
   help,
   "--help",
   "-h",
   "Show the help message",
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
find_option_by_cmdline_string(const char *opt_string)
{
   struct elfhack_option *opt = options_head;

   if (!opt_string)
      return NULL;

   while (opt) {

      assert(opt->long_opt);

      if (!strcmp(opt_string, opt->long_opt)) {
         return opt;
      }

      if (opt->short_opt && !strcmp(opt_string, opt->short_opt)) {
         return opt;
      }

      opt = opt->next;
   }

   return NULL;
}

struct elfhack_option *
find_option_by_name(const char *name)
{
   struct elfhack_option *opt = options_head;

   while (opt) {

      if (!strcmp(opt->name, name))
         return opt;

      opt = opt->next;
   }

   return NULL;
}

bool
get_boolean_option_val(const char *name)
{
   struct elfhack_option *opt = find_option_by_name(name);

   if (opt) {
      return opt->boolean_value;
   }

   return false;
}

int
get_enum_option_val(const char *name)
{
   struct elfhack_option *opt = find_option_by_name(name);

   if (opt) {
      return opt->enum_value;
   }

   return 0;
}

int
process_option_type_action(struct elf_file_info *nfo,
                           struct elfhack_option *opt,
                           int *argc,
                           char **argv)
{
   int rc;
   assert(opt->type == ELFHACK_ACTION);

   switch (opt->nargs) {
      case 0:
         rc = ((cmd_func_0)opt->func)(nfo);
         break;
      case 1:
         rc = ((cmd_func_1)opt->func)(nfo, argv[0]);
         break;
      case 2:
         rc = ((cmd_func_2)opt->func)(nfo, argv[0], argv[1]);
         break;
      case 3:
         rc = ((cmd_func_3)opt->func)(nfo, argv[0], argv[1], argv[2]);
         break;
      default:
         abort();
   }

   *argc -= opt->nargs;
   return rc;
}

int
process_option_type_flag(struct elf_file_info *nfo,
                         struct elfhack_option *opt,
                         int *argc,
                         char **argv)
{
   UNUSED_VARIABLE(nfo);
   UNUSED_VARIABLE(argv);

   assert(opt->type == ELFHACK_FLAG);

   if (*argc > 0 && !strcmp(argv[0], "false")) {
      opt->boolean_value = false;
      (*argc)--;
   } else if (*argc > 0 && !strcmp(argv[0], "true")) {
      opt->boolean_value = true;
      (*argc)--;
   } else {
      /* No extra param, assume implict true */
      opt->boolean_value = true;
   }

   return 0;
}

int
process_option_type_enum(struct elf_file_info *nfo,
                         struct elfhack_option *opt,
                         int *argc,
                         char **argv)
{
   UNUSED_VARIABLE(nfo);
   int choice = -1;

   for (int i = 0; opt->enum_choices[i]; i++) {
      if (!strcmp(argv[0], opt->enum_choices[i])) {
         choice = i;
         break;
      }
   }

   if (choice < 0) {
      fprintf(stderr,
              "ERROR: invalid choice '%s' for enum option '%s'\n",
              argv[0], opt->long_opt);
      return 1;
   }

   opt->enum_value = choice;
   *argc -= 1;
   return 0;
}

int
get_nargs_for_option_type(struct elfhack_option *opt)
{
   switch (opt->type) {
      case ELFHACK_ACTION:
         return opt->nargs;
      case ELFHACK_FLAG:
         return 0;
      case ELFHACK_ENUM:
         return 1;
      default:
         abort(); /* unknown type */
   }
}

int
process_all_options(struct elf_file_info *nfo,
                    int argc,
                    char **argv)
{
   struct elfhack_option *opt = NULL;
   const char *opt_string;
   int rc = 0;
   int nargs;
   int argc_new;

   while (argc > 0 && argv[0]) {

      opt_string = argv[0];
      opt = find_option_by_cmdline_string(opt_string);
      argc--; argv++;

      if (!opt) {
         printf("ERROR: option '%s' not recognized\n", opt_string);
         show_help(NULL);
         return 1;
      }

      nargs = get_nargs_for_option_type(opt);

      if (argc < nargs) {
         fprintf(stderr,
                 "ERROR: Invalid number of arguments for %s "
                 "(expected: %d, got: %d).\n", opt_string, nargs, argc);
         return 1;
      }

      argc_new = argc;
      switch (opt->type) {
         case ELFHACK_ACTION:
            rc = process_option_type_action(nfo, opt, &argc_new, argv);
            break;
         case ELFHACK_FLAG:
            rc = process_option_type_flag(nfo, opt, &argc_new, argv);
            break;
         case ELFHACK_ENUM:
            rc = process_option_type_enum(nfo, opt, &argc_new, argv);
            break;
         default:
            abort(); /* unknown type */
      }

      if (rc) {
         /* We got an error, stop processing. */
         break;
      }

      /* The remaining arguments cannot be less then 0 */
      assert(argc_new >= 0);

      /* The option must have consumed at least `nargs` */
      assert(argc - argc_new >= nargs);

      argv += (argc - argc_new);
      argc = argc_new;
   }

   return rc;
}

static void
validate_tool_options(void)
{
   struct elfhack_option *opt = options_head;
   struct elfhack_option *t;

   while (opt) {

      t = find_option_by_cmdline_string(opt->long_opt);
      if (t != opt) {
         fprintf(stderr,
                 "FATAL: long option '%s' is used by multiple "
                 "options/commands", opt->long_opt);
         abort();
      }

      if (opt->short_opt) {
         t = find_option_by_cmdline_string(opt->short_opt);
         if (t != opt) {
            fprintf(stderr,
                  "FATAL: short option '%s' is used both by "
                  "'%s' and by '%s'\n",
                  opt->short_opt, opt->long_opt, t->long_opt);
            abort();
         }
      }

      opt = opt->next;
   }
}

int
main(int argc, char **argv)
{
   struct elf_file_info nfo = {0};
   struct stat statbuf;
   size_t page_size;
   int rc;

   validate_tool_options();

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

   rc = process_all_options(&nfo, argc - 2, argv + 2);

end:
   if (munmap(nfo.vaddr, nfo.mmap_size) < 0) {
      perror("munmap() failed");
   }

   close(nfo.fd);
   return rc;
}
