/**
 * (C) 2007-22 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */

// taken from https://github.com/kokke/tiny-regex-c
// under Unlicense as of August 4, 2020

/*
 *
 * Mini regex-module inspired by Rob Pike's regex code described in:
 *
 * http://www.cs.princeton.edu/courses/archive/spr09/cos333/beautiful.html
 *
 *
 *
 * Supports:
 * ---------
 *     '.'        Dot, matches any character
 *     '^'        Start anchor, matches beginning of string
 *     '$'        End anchor, matches end of string
 *     '*'        Asterisk, match zero or more (greedy)
 *     '+'        Plus, match one or more (greedy)
 *     '?'        Question, match zero or one (non-greedy)
 *     '[abc]'    Character class, match if one of {'a', 'b', 'c'}
 *     '[^abc]'   Inverted class, match if NOT one of {'a', 'b', 'c'} -- NOTE: feature is currently broken!
 *     '[a-zA-Z]' Character ranges, the character set of the ranges { a-z | A-Z }
 *     '\s'       Whitespace, \t \f \r \n \v and spaces
 *     '\S'       Non-whitespace
 *     '\w'       Alphanumeric, [a-zA-Z0-9_]
 *     '\W'       Non-alphanumeric
 *     '\d'       Digits, [0-9]
 *     '\D'       Non-digits
 *
 *
 */

#ifndef _N2N_REGEX_
#define _N2N_REGEX_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

/* Compile regex string pattern to a regex_t-array. */
re_t re_compile (const char* pattern);


/* Find matches of the compiled pattern inside text. */
int re_matchp (re_t pattern, const char* text, int* matchlenght);


/* Find matches of the txt pattern inside text (will compile automatically first). */
int  re_match (const char* pattern, const char* text, int* matchlenght);


#ifdef __cplusplus
}
#endif

#endif
