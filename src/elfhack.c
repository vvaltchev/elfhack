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
#include "elfhack/misc.h"

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

      if (!strcmp(opt->name, name)) {
         return opt;
      }

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

const char *
get_string_option_val(const char *name)
{
   struct elfhack_option *opt = find_option_by_name(name);

   if (opt) {
      return opt->string_value;
   }

   return NULL;
}

int
process_option_type_action(struct elf_file_info *nfo,
                           struct elfhack_option *opt,
                           bool const_processing,
                           int *argc,
                           char **argv)
{
   int rc = 0;
   assert(opt->type == ELFHACK_ACTION);

   if (!const_processing) {
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
   }

   *argc -= opt->nargs;
   return rc;
}

int
process_option_type_flag(struct elf_file_info *nfo,
                         struct elfhack_option *opt,
                         bool const_processing,
                         int *argc,
                         char **argv)
{
   UNUSED_VARIABLE(nfo);
   UNUSED_VARIABLE(argv);

   assert(opt->type == ELFHACK_FLAG);

   if (*argc > 0 && !strcmp(argv[0], "false")) {

      if (!const_processing || opt->is_const)
         opt->boolean_value = false;

      (*argc)--;

   } else if (*argc > 0 && !strcmp(argv[0], "true")) {

      if (!const_processing || opt->is_const)
         opt->boolean_value = true;

      (*argc)--;

   } else {

      if (!const_processing || opt->is_const) {
         /* No extra param, assume implict true */
         opt->boolean_value = true;
      }
   }

   opt->set_once = true;
   return 0;
}

int
process_option_type_enum(struct elf_file_info *nfo,
                         struct elfhack_option *opt,
                         bool const_processing,
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

   if (!const_processing || opt->is_const) {
      opt->enum_value = choice;
      opt->set_once = true;
   }

   *argc -= 1;
   return 0;
}

int
process_option_type_string(struct elf_file_info *nfo,
                           struct elfhack_option *opt,
                           bool const_processing,
                           int *argc,
                           char **argv)
{
   UNUSED_VARIABLE(nfo);

   if (!const_processing || opt->is_const) {
      opt->string_value = argv[0];
      opt->set_once = true;
   }

   *argc -= 1;
   return 0;
}

void register_option(struct elfhack_option *opt)
{
   if (!options_tail) {

      assert(!options_head);
      options_head = opt;
      options_tail = opt;

   } else {

      options_tail->next = opt;
      options_tail = opt;
   }

   switch (opt->type) {

      case ELFHACK_ACTION:
         opt->proc = &process_option_type_action;
         break;

      case ELFHACK_FLAG:
         opt->proc = &process_option_type_flag;
         break;

      case ELFHACK_ENUM:
         opt->proc = &process_option_type_enum;
         break;

      case ELFHACK_STRING:
         opt->proc = &process_option_type_string;
         break;

      default:
         abort();
   }
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
      case ELFHACK_STRING:
         return 1;
      default:
         abort(); /* unknown type */
   }
}

REGISTER_STRING_FLAG(
   output,
   "--output",
   "-o",
   true, /* is_const */
   "<output file>: without this, <file> will be modified in place"
)

int
process_all_options(struct elf_file_info *nfo,
                    int argc,
                    char **argv,
                    bool const_processing)
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

      if (const_processing && opt->is_const && opt->set_once) {
         fprintf(stderr,
                 "Error: const option %s set more than once\n",
                 opt->name);
         return 1;
      }

      argc_new = argc;
      opt->proc(nfo, opt, const_processing, &argc_new, argv);

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
   const char *dest_file;
   const char *elf_file;
   int rc;

   validate_tool_options();

   if (argc <= 1 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
      show_help(NULL);
      return 1;
   }

   rc = process_all_options(NULL, argc - 2, argv + 2, true);
   if (rc) {
      return 1;
   }

   elf_file = argv[1];
   dest_file = get_string_option_val("output");

   if (dest_file) {
      if (file_copy(elf_file, dest_file)) {
         return 1;
      }
      elf_file = dest_file;
   }

   nfo.path = elf_file;
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

   rc = process_all_options(&nfo, argc - 2, argv + 2, false);

end:
   if (munmap(nfo.vaddr, nfo.mmap_size) < 0) {
      perror("munmap() failed");
   }

   close(nfo.fd);
   return rc;
}
