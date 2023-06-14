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


#define json_str_is_whitespace(x)                     x == '\r' || x == '\n' || x == '\t' || x == ' '
#define json_str_is_numeral(x)                        (x >= '0' && x <= '9') || x == 'e' || x == 'E' \
                                                      || x == '.'  || x == '+' || x == '-'
#define json_str_remove_whitespace_calc_offset(x, y)  while(json_str_is_whitespace(*x)) { x++; y++; }


typedef enum {
    JSON_STRING = 0,
    JSON_DOUBLE,
    JSON_OBJECT
} json_value_type;

typedef struct _jsonobject {
    struct _jsonpair *pairs;
    int count;
} json_object_t;

typedef struct _jsonpair {
    char *key;
    union _jsonvalue *value;
    json_value_type type;
} json_pair_t;

typedef union _jsonvalue {
    char *string_value;
    double double_value;
    struct _jsonobject *json_object;
} json_value_t;


json_object_t *json_parse (char *str);
void json_free (json_object_t *obj);


#endif
