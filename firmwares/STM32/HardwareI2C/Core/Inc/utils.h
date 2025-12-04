#ifndef __UTILS_H
#define __UTILS_H

/* 插入 symbol */
#define ANGR_MARKER(name) __asm__ volatile (".global " #name "\n" #name ":")

#endif