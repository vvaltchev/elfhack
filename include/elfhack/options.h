/* SPDX-License-Identifier: BSD-2-Clause */

#pragma once
#include <stdbool.h>

enum elfhack_option_type {
   ELFHACK_ACTION,
   ELFHACK_FLAG,
   ELFHACK_ENUM,
   ELFHACK_STRING,
};

struct elf_file_info;
struct elfhack_option;

typedef int (*opt_process_func)(struct elf_file_info *,
                                struct elfhack_option *,
                                bool const_processing,
                                int *argc_new,
                                char **argv);

struct elfhack_option {

   struct elfhack_option *next;
   enum elfhack_option_type type;

   const char *name;      /* internal option name */
   const char *long_opt;  /* long option like --rename-section */
   const char *short_opt; /* short option like -rr */
   const char *help;      /* help message */
   bool is_const;         /* is the option const?
                           * const options are processed first */
   bool set_once;         /* has the value been set once? */
   opt_process_func proc; /* function to process this option */

   union {

      /* type == ELFHACK_ACTION */
      struct {
         int nargs;             /* number of parameters */
         void *func;            /* function pointer */
      };

      /* type == ELFHACK_FLAG */
      bool boolean_value;       /* always `false` as default. */

      /* type == ELFHACK_ENUM */
      struct {
         int enum_value;
         const char **enum_choices; /* NULL-terminated */
      };

      /* type == ELFHACK_STRING */
      const char *string_value;
   };
};

void register_option(struct elfhack_option *opt);
struct elfhack_option *find_option_by_name(const char *name);
bool get_boolean_option_val(const char *name);
int get_enum_option_val(const char *name);
const char *get_string_option_val(const char *name);

#define REGISTER_CMD(n, opt1, opt2, help_str, nargs_val, handler)    \
   static struct elfhack_option __cmd_##n = {                        \
      .next = NULL,                                                  \
      .type = ELFHACK_ACTION,                                        \
      .name = #n,                                                    \
      .long_opt = opt1,                                              \
      .short_opt = opt2,                                             \
      .help = help_str,                                              \
      .nargs = nargs_val,                                            \
      .func = handler,                                               \
   };                                                                \
   static void __attribute__((constructor))                          \
   __register_cmd_##n(void) {                                        \
      register_option(&__cmd_##n);                                   \
   }

#define REGISTER_BOOL_FLAG(n, opt1, opt2, const, help_str)           \
   static struct elfhack_option __flag_##n = {                       \
      .next = NULL,                                                  \
      .type = ELFHACK_FLAG,                                          \
      .name = #n,                                                    \
      .long_opt = opt1,                                              \
      .short_opt = opt2,                                             \
      .help = help_str,                                              \
      .is_const = const,                                             \
   };                                                                \
   static void __attribute__((constructor))                          \
   __register_flag_##n(void) {                                       \
      register_option(&__flag_##n);                                  \
   }

#define REGISTER_ENUM_FLAG(n, opt1, opt2, const, help_str, choices)  \
   static struct elfhack_option __enum_##n = {                       \
      .next = NULL,                                                  \
      .type = ELFHACK_ENUM,                                          \
      .name = #n,                                                    \
      .long_opt = opt1,                                              \
      .short_opt = opt2,                                             \
      .help = help_str,                                              \
      .is_const = const,                                             \
      .enum_choices = choices,                                       \
   };                                                                \
   static void __attribute__((constructor))                          \
   __register_enum_##n(void) {                                       \
      register_option(&__enum_##n);                                  \
   }

#define REGISTER_STRING_FLAG(n, opt1, opt2, const, help_str)         \
   static struct elfhack_option __string_##n = {                     \
      .next = NULL,                                                  \
      .type = ELFHACK_STRING,                                        \
      .name = #n,                                                    \
      .long_opt = opt1,                                              \
      .short_opt = opt2,                                             \
      .help = help_str,                                              \
      .is_const = const,                                             \
   };                                                                \
   static void __attribute__((constructor))                          \
   __register_string_##n(void) {                                     \
      register_option(&__string_##n);                                \
   }
