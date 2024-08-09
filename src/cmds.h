/* SPDX-License-Identifier: BSD-2-Clause */

#pragma once

struct elfhack_cmd {

   struct elfhack_cmd *next;

   const char *opt;
   const char *help;
   int nargs;
   void *func;
};

void register_cmd_struct(struct elfhack_cmd *cmd);


#define REGISTER_CMD(name, long_opt, help_str, nargs_val, handler)   \
   static struct elfhack_cmd __cmd_##name = {                        \
      .next = NULL,                                                  \
      .opt = long_opt,                                               \
      .help = help_str,                                              \
      .nargs = nargs_val,                                            \
      .func = handler                                                \
   };                                                                \
   static void __attribute__((constructor))                          \
   __register_cmd_##name(void) {                                     \
      register_cmd_struct(&__cmd_##name);                            \
   }
