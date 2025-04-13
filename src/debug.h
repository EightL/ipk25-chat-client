/**
 * @file debug.h
 * @brief Debug printing utility for the IPK25-CHAT client
 *
 * This file provides a debug printing macro that can be conditionally
 * compiled based on the DEBUG_PRINT preprocessor flag. When enabled,
 * it outputs detailed debug information including file, line number,
 * and function name.
 *
 * @author xsevcim00
 */

 #ifndef DEBUG_H
 #define DEBUG_H
 
 /**
  * @brief Debug print macro
  *
  * Provides a printf-style debugging facility that includes source location information.
  * When DEBUG_PRINT is defined, it outputs to stderr. Otherwise, the macro expands to nothing.
  *
  * @param format printf-style format string
  * @param ... Variable arguments for the format string
  */
 #ifdef DEBUG_PRINT
 #define printf_debug(format, ...) fprintf(stderr, "%s:%-4d | %15s | " format "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__)
 #else
 #define printf_debug(format, ...) ((void)0)
 #endif
 
 #endif // DEBUG_H