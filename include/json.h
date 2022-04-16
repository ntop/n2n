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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


// taken from (and modified)
// https://github.com/Logan007/C-Simple-JSON-Parser
// which is declared license-free code by the author according to
// https://github.com/forkachild/C-Simple-JSON-Parser/issues/3#issuecomment-1073520808


#ifndef JSON_H
#define JSON_H


#include <string.h>
#include <stdlib.h>

#ifndef __cplusplus
typedef char*                                   string;
typedef unsigned char                           bool;
#define true                                    (1)
#define false                                   (0)
#define TRUE                                    true
#define FALSE                                   false
#endif

#define new(x)                                  (x *) malloc(sizeof(x))
#define newWithSize(x, y)                       (x *) malloc(y * sizeof(x))
#define renewWithSize(x, y, z)                  (y *) realloc(x, z * sizeof(y))
#define isWhitespace(x)                         x == '\r' || x == '\n' || x == '\t' || x == ' '
#define isNumeral(x)                            (x >= '0' && x <= '9') || x == 'e' || x == 'E' \
                                                || x == '.'  || x == '+' || x == '-'
#define removeWhitespace(x)                     while(isWhitespace(*x)) x++
#define removeWhitespaceCalcOffset(x, y)        while(isWhitespace(*x)) { x++; y++; }

typedef char                                    character;

struct _jsonobject;
struct _jsonpair;
union _jsonvalue;

typedef enum {
    JSON_STRING = 0,
    JSON_DOUBLE,
    JSON_OBJECT
} JSONValueType;

typedef struct _jsonobject {
    struct _jsonpair *pairs;
    int count;
} json_object_t;

typedef struct _jsonpair {
    string key;
    union _jsonvalue *value;
    JSONValueType type;
} json_pair_t;

typedef union _jsonvalue {
    string string_value;
    double double_value;
    struct _jsonobject *json_object;
} json_value_t;


json_object_t *json_parse (string str);
void json_free (json_object_t *obj);


#endif
