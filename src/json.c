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


#include "json.h"


static int json_str_next_occurence (char *str, char ch);
static int json_str_next_non_numeral (char *str);
static json_object_t *_json_parse (char *str, int *offset);


json_object_t *json_parse (char *str) {

    int offset = 0;

    json_object_t *temp_obj = _json_parse(str, &offset);

    return temp_obj;
}


void json_free (json_object_t *obj) {

    int i;

    if(obj == NULL)
        return;

    if(obj->pairs == NULL) {
        free(obj);
        return;
    }

    for(i = 0; i < obj->count; i++) {
        if(obj->pairs[i].key != NULL)
            free(obj->pairs[i].key);
        if(obj->pairs[i].value != NULL) {
            switch(obj->pairs[i].type) {
                case JSON_STRING:
                    free(obj->pairs[i].value->string_value);
                    break;
                case JSON_DOUBLE:
                    break;
                case JSON_OBJECT:
                    json_free(obj->pairs[i].value->json_object);
            }
            free(obj->pairs[i].value);
        }
    }
}


static int json_str_next_occurence (char *str, char ch) {

    int pos = 0;

    if(str == NULL)
        return -1;

    while(*str != ch && *str != '\0') {
        str++;
        pos++;
    }

    return (*str == '\0') ? -1 : pos;
}


static int json_str_next_non_numeral (char *str) {

    int pos = 0;

    if(str == NULL)
        return -1;

    while((json_str_is_numeral(*str)) && (*str != '\0')) {
        str++;
        pos++;
    }
    return (*str == '\0') ? -1 : pos;
}


static json_object_t *_json_parse (char *str, int *offset) {

    int _offset = 0;

    json_object_t *obj = (json_object_t*)malloc(sizeof(json_object_t));
    obj->count = 1;
    obj->pairs = (json_pair_t*)malloc(sizeof(json_pair_t));

    while(*str != '\0') {
        json_str_remove_whitespace_calc_offset(str, _offset);
        if(*str == '{') {
            str++;
            _offset++;
        } else if(*str == '"') {

            int i = json_str_next_occurence(++str, '"');
            if(i <= 0) {
                json_free(obj);
                return NULL;
            }

            json_pair_t tempPtr = obj->pairs[obj->count - 1];

            tempPtr.key = (char*)malloc((i + 1) * sizeof(char));
            memcpy(tempPtr.key, str, i * sizeof(char));
            tempPtr.key[i] = '\0';

            str += i + 1;
            _offset += i + 2;

            i = json_str_next_occurence(str, ':');
            if(i == -1)
                return NULL;
            str += i + 1;
            _offset += i + 1;

            json_str_remove_whitespace_calc_offset(str, _offset);

            if(*str == '{') {
                int _offsetBeforeParsingChildObject = _offset;
                int _sizeOfChildObject;

                tempPtr.value = (json_value_t*)malloc(sizeof(json_value_t));
                tempPtr.type = JSON_OBJECT;
                tempPtr.value->json_object = _json_parse(str, &_offset);
                if(tempPtr.value->json_object == NULL) {
                    json_free(obj);
                    return NULL;
                }
                // Advance the string pointer by the size of the processed child object
                _sizeOfChildObject = _offset - _offsetBeforeParsingChildObject;
                str += _sizeOfChildObject;
            } else if(*str == '"') {
                i = json_str_next_occurence(++str, '"');
                if(i == -1) {
                    json_free(obj);
                    return NULL;
                }
                tempPtr.value = (json_value_t*)malloc(sizeof(json_value_t));
                tempPtr.type = JSON_STRING;
                tempPtr.value->string_value = (char*)malloc((i + 1) * sizeof(char));
                memcpy(tempPtr.value->string_value, str, i * sizeof(char));
                tempPtr.value->string_value[i] = '\0';
                str += i + 1;
                _offset += i + 2;
            } else if(json_str_is_numeral(*str)) {
                i = json_str_next_non_numeral(str);
                if(i == -1) {
                    json_free(obj);
                    return NULL;
                }
                char *tempStr = (char*)malloc((i + 1) * sizeof(char));
                memcpy(tempStr, str, i * sizeof(char));
                tempStr[i] = '\0';

                tempPtr.value = (json_value_t*)malloc(sizeof(json_value_t));
                tempPtr.type = JSON_DOUBLE;
                tempPtr.value->double_value = atof(tempStr);

                free(tempStr);
                str += i;
                _offset += i + 1;
            }
            obj->pairs[obj->count - 1] = tempPtr;

        } else if (*str == ',') {
            obj->count++;
            obj->pairs = (json_pair_t*)realloc(obj->pairs, obj->count * sizeof(json_pair_t));
            str++;
            _offset++;
        } else if (*str == '}') {
            (*offset) += _offset + 1;
            return obj;
        }
    }
    return obj;
}
