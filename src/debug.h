#ifndef DEBUG_H
#define DEBUG_H

#ifdef DEBUG_PRINT
#define printf_debug(format, ...) fprintf(stderr, "%s:%-4d | %15s | " format "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#else
#define printf_debug(format, ...) (0)
#endif

#endif // DEBUG_H