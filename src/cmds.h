/* SPDX-License-Identifier: BSD-2-Clause */

#pragma once

struct elfhack_option {

   struct elfhack_option *next;

   const char *long_opt;
   const char *short_opt;
   const char *help;
   int nargs;
   void *func;
};

void register_option(struct elfhack_option *cmd);


#define REGISTER_CMD(name, opt1, opt2, help_str, nargs_val, handler) \
   static struct elfhack_option __cmd_##name = {                     \
      .next = NULL,                                                  \
      .long_opt = opt1,                                              \
      .short_opt = opt2,                                             \
      .help = help_str,                                              \
      .nargs = nargs_val,                                            \
      .func = handler                                                \
   };                                                                \
   static void __attribute__((constructor))                          \
   __register_cmd_##name(void) {                                     \
      register_option(&__cmd_##name);                                \
   }
