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
 *     '^'        Start anchor, matches beginning of string -- NOTE: currently disabled (checking for full matches anyway)
 *     '$'        End anchor, matches end of string         -- NOTE: currently disabled (checking for full matches anyway)
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


#include "n2n.h"
#include "n2n_regex.h"

/* Definitions: */

#define MAX_REGEXP_OBJECTS            30        /* Max number of regex symbols in expression. */
#define MAX_CHAR_CLASS_LEN            40        /* Max length of character-class buffer in.     */


enum { UNUSED, DOT, BEGIN, END, QUESTIONMARK, STAR, PLUS, CHAR_TYPE, CHAR_CLASS, INV_CHAR_CLASS, DIGIT, NOT_DIGIT, ALPHA, NOT_ALPHA, WHITESPACE, NOT_WHITESPACE, /* BRANCH */ };

typedef struct regex_t {
    unsigned char    type;     /* CHAR_TYPE, STAR, etc.  */
    union {
        unsigned char  ch;     /* the character itself               */
        unsigned char* ccl;    /* OR a pointer to characters in class */
    };
} regex_t;



/* Private function declarations: */
static int matchpattern (regex_t* pattern, const char* text, int* matchlength);
static int matchcharclass (char c, const char* str);
static int matchstar (regex_t p, regex_t* pattern, const char* text, int* matchlength);
static int matchplus (regex_t p, regex_t* pattern, const char* text, int* matchlength);
static int matchone (regex_t p, char c);
static int matchdigit (char c);
static int matchalpha (char c);
static int matchwhitespace (char c);
static int matchmetachar (char c, const char* str);
static int matchrange (char c, const char* str);
static int matchdot (char c);
static int ismetachar (char c);



/* Public functions: */
int re_match (const char* pattern, const char* text, int* matchlength) {

    re_t re_p;    /* pointer to (to be created) copy of compiled regex */
    int ret = -1;

    re_p = re_compile (pattern);
    ret    = re_matchp(re_p, text, matchlength);
    free(re_p);

    return(ret);
}

int re_matchp (re_t pattern, const char* text, int* matchlength) {

    *matchlength = 0;

    if(pattern != 0) {
        if(pattern[0].type == BEGIN) {
            return ((matchpattern(&pattern[1], text, matchlength)) ? 0 : -1);
        } else {
            int idx = -1;

            do {
                idx += 1;

                if(matchpattern(pattern, text, matchlength)) {
                    if(text[0] == '\0') {
                        return -1;
                    }
                    return idx;
                }
            } while(*text++ != '\0');
        }
    }

    return -1;
}

re_t re_compile (const char* pattern) {

    /* The sizes of the two static arrays below substantiates the static RAM usage of this module.
       MAX_REGEXP_OBJECTS is the max number of symbols in the expression.
       MAX_CHAR_CLASS_LEN determines the size of buffer for chars in all char-classes in the expression. */
    static regex_t re_compiled[MAX_REGEXP_OBJECTS];
    re_t re_p;    /* pointer to (to be created) copy of compiled regex in re_compiled */

    static unsigned char ccl_buf[MAX_CHAR_CLASS_LEN];
    int ccl_bufidx = 1;

    char c;       /* current char in pattern     */
    int i = 0;    /* index into pattern          */
    int j = 0;    /* index into re_compiled      */

    while(pattern[i] != '\0' && (j + 1 < MAX_REGEXP_OBJECTS)) {
        c = pattern[i];

        switch(c) {
            /* Meta-characters: */
            //  case '^': { re_compiled[j].type = BEGIN; } break; <-- disabled (always full matches)
            //  case '$': { re_compiled[j].type = END;   } break; <-- disabled (always full matches)
            case '.': {  re_compiled[j].type = DOT;           } break;
            case '*': {  re_compiled[j].type = STAR;          } break;
            case '+': {  re_compiled[j].type = PLUS;          } break;
            case '?': {  re_compiled[j].type = QUESTIONMARK;  } break;
            /*  case '|': { re_compiled[j].type = BRANCH; } break; <-- not working properly */

            /* Escaped character-classes (\s \w ...): */
            case '\\': {
                if(pattern[i + 1] != '\0') {
                    /* Skip the escape-char '\\' */
                    i += 1;
                    /* ... and check the next */
                    switch(pattern[i]) {
                        /* Meta-character: */
                        case 'd': {  re_compiled[j].type = DIGIT;           } break;
                        case 'D': {  re_compiled[j].type = NOT_DIGIT;       } break;
                        case 'w': {  re_compiled[j].type = ALPHA;           } break;
                        case 'W': {  re_compiled[j].type = NOT_ALPHA;       } break;
                        case 's': {  re_compiled[j].type = WHITESPACE;      } break;
                        case 'S': {  re_compiled[j].type = NOT_WHITESPACE;  } break;

                        /* Escaped character, e.g. '.' */
                        default: {
                            re_compiled[j].type = CHAR_TYPE;
                            re_compiled[j].ch = pattern[i];
                        } break;
                    }
                }
                /* '\\' as last char in pattern -> invalid regular expression. */
                /*
                else
                {
                    re_compiled[j].type = CHAR_TYPE;
                    re_compiled[j].ch = pattern[i];
                }
                */
            } break;

            /* Character class: */
            case '[': {
                /* Remember where the char-buffer starts. */
                int buf_begin = ccl_bufidx;

                /* Look-ahead to determine if negated */
                if(pattern[i+1] == '^') {
                    re_compiled[j].type = INV_CHAR_CLASS;
                    i += 1; /* Increment i to avoid including '^' in the char-buffer */
                } else {
                    re_compiled[j].type = CHAR_CLASS;
                }

                /* Copy characters inside [..] to buffer */
                while((pattern[++i] != ']')
                      && (pattern[i] != '\0')) /* Missing ] */
                {
                    if(pattern[i] == '\\') {
                        if(ccl_bufidx >= MAX_CHAR_CLASS_LEN - 1) {
                            //fputs("exceeded internal buffer!\n", stderr);
                            return 0;
                        }
                        ccl_buf[ccl_bufidx++] = pattern[i++];
                    } else if(ccl_bufidx >= MAX_CHAR_CLASS_LEN) {
                            //fputs("exceeded internal buffer!\n", stderr);
                            return 0;
                    }
                    ccl_buf[ccl_bufidx++] = pattern[i];
                }
                if(ccl_bufidx >= MAX_CHAR_CLASS_LEN) {
                        /* Catches cases such as [00000000000000000000000000000000000000][ */
                        //fputs("exceeded internal buffer!\n", stderr);
                        return 0;
                }
                /* Null-terminate string end */
                ccl_buf[ccl_bufidx++] = 0;
                re_compiled[j].ccl = &ccl_buf[buf_begin];
            } break;

            /* Other characters: */
            default: {
                re_compiled[j].type = CHAR_TYPE;
                re_compiled[j].ch = c;
            } break;
        }
        i += 1;
        j += 1;
    }
    /* 'UNUSED' is a sentinel used to indicate end-of-pattern */
    re_compiled[j].type = UNUSED;

    re_p = (re_t)calloc(1, sizeof(re_compiled));
    memcpy (re_p, re_compiled, sizeof(re_compiled));

    return (re_t) re_p;
}

void re_print (regex_t* pattern) {

    const char* types[] = { "UNUSED", "DOT", "BEGIN", "END", "QUESTIONMARK", "STAR", "PLUS", "CHAR_TYPE", "CHAR_CLASS", "INV_CHAR_CLASS", "DIGIT", "NOT_DIGIT", "ALPHA", "NOT_ALPHA", "WHITESPACE" , "NOT_WHITESPACE", /* "BRANCH" */ };
    int i;
    int j;
    char c;

    for(i = 0; i < MAX_REGEXP_OBJECTS; ++i) {
        if(pattern[i].type == UNUSED) {
            break;
        }

        printf("type: %s", types[pattern[i].type]);
        if((pattern[i].type == CHAR_CLASS) || (pattern[i].type == INV_CHAR_CLASS)) {
            printf(" [");
            for(j = 0; j < MAX_CHAR_CLASS_LEN; ++j) {
                c = pattern[i].ccl[j];
                if((c == '\0') || (c == ']')) {
                    break;
                }
                printf("%c", c);
            }
            printf("]");
        } else if(pattern[i].type == CHAR_TYPE) {
            printf(" '%c'", pattern[i].ch);
        }
        printf("\n");
    }
}



/* Private functions: */
static int matchdigit (char c) {

    return ((c >= '0') && (c <= '9'));
}

static int matchalpha (char c) {

    return ((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z'));
}

static int matchwhitespace (char c) {

    return ((c == ' ') || (c == '\t') || (c == '\n') || (c == '\r') || (c == '\f') || (c == '\v'));
}

static int matchalphanum (char c) {

    return ((c == '_') || matchalpha(c) || matchdigit(c));
}

static int matchrange (char c, const char* str) {

    return ((c != '-') && (str[0] != '\0') && (str[0] != '-') &&
            (str[1] == '-') && (str[1] != '\0') &&
            (str[2] != '\0') && ((c >= str[0]) && (c <= str[2])));
}

static int matchdot (char c) {

    return ((c != '\n') && (c != '\r'));
}

static int ismetachar (char c) {

    return ((c == 's') || (c == 'S') || (c == 'w') || (c == 'W') || (c == 'd') || (c == 'D'));
}

static int matchmetachar (char c, const char* str) {

    switch(str[0]) {
        case 'd': return  matchdigit(c);
        case 'D': return !matchdigit(c);
        case 'w': return  matchalphanum(c);
        case 'W': return !matchalphanum(c);
        case 's': return  matchwhitespace(c);
        case 'S': return !matchwhitespace(c);
        default:  return (c == str[0]);
    }
}

static int matchcharclass (char c, const char* str) {

    do {
        if(matchrange(c, str)) {
            return 1;
        } else if(str[0] == '\\') {
            /* Escape-char: increment str-ptr and match on next char */
            str += 1;
            if(matchmetachar(c, str)) {
                return 1;
            } else if((c == str[0]) && !ismetachar(c)) {
                return 1;
            }
        } else if(c == str[0]) {
            if(c == '-') {
                return ((str[-1] == '\0') || (str[1] == '\0'));
            } else {
                return 1;
            }
        }
    } while(*str++ != '\0');

    return 0;
}

static int matchone (regex_t p, char c) {

    switch(p.type) {
        case DOT:            return  matchdot(c);
        case CHAR_CLASS:     return  matchcharclass(c, (const char*)p.ccl);
        case INV_CHAR_CLASS: return !matchcharclass(c, (const char*)p.ccl);
        case DIGIT:          return  matchdigit(c);
        case NOT_DIGIT:      return !matchdigit(c);
        case ALPHA:          return  matchalphanum(c);
        case NOT_ALPHA:      return !matchalphanum(c);
        case WHITESPACE:     return  matchwhitespace(c);
        case NOT_WHITESPACE: return !matchwhitespace(c);
        default:             return  (p.ch == c);
    }
}

static int matchstar (regex_t p, regex_t* pattern, const char* text, int* matchlength) {

    int prelen = *matchlength;
    const char* prepoint = text;

    while((text[0] != '\0') && matchone(p, *text)) {
        text++;
        (*matchlength)++;
    }

    while(text >= prepoint) {
        if(matchpattern(pattern, text--, matchlength)) {
            return 1;
        }
        (*matchlength)--;
    }

    *matchlength = prelen;

    return 0;
}

static int matchplus (regex_t p, regex_t* pattern, const char* text, int* matchlength) {

    const char* prepoint = text;

    while((text[0] != '\0') && matchone(p, *text)) {
        text++;
        (*matchlength)++;
    }

    while(text > prepoint) {
        if(matchpattern(pattern, text--, matchlength)) {
            return 1;
        }
        (*matchlength)--;
    }

    return 0;
}

static int matchquestion (regex_t p, regex_t* pattern, const char* text, int* matchlength) {

    if(p.type == UNUSED) {
        return 1;
    }

    if(matchpattern(pattern, text, matchlength)) {
        return 1;
    }

    if(*text && matchone(p, *text++)) {
        if(matchpattern(pattern, text, matchlength)) {
            (*matchlength)++;
            return 1;
        }
    }

    return 0;
}


#if 0

/* Recursive matching */
static int matchpattern (regex_t* pattern, const char* text, int *matchlength) {

    int pre = *matchlength;

    if((pattern[0].type == UNUSED) || (pattern[1].type == QUESTIONMARK)) {
        return matchquestion(pattern[1], &pattern[2], text, matchlength);
    } else if(pattern[1].type == STAR) {
        return matchstar(pattern[0], &pattern[2], text, matchlength);
    } else if(pattern[1].type == PLUS) {
        return matchplus(pattern[0], &pattern[2], text, matchlength);
    } else if((pattern[0].type == END) && pattern[1].type == UNUSED) {
        return text[0] == '\0';
    } else if((text[0] != '\0') && matchone(pattern[0], text[0])) {
        (*matchlength)++;
        return matchpattern(&pattern[1], text+1);
    } else {
        *matchlength = pre;
        return 0;
    }
}

#else

/* Iterative matching */
static int matchpattern (regex_t* pattern, const char* text, int* matchlength) {

    int pre = *matchlength;

    do {
        if((pattern[0].type == UNUSED) || (pattern[1].type == QUESTIONMARK)) {
            return matchquestion(pattern[0], &pattern[2], text, matchlength);
        } else if(pattern[1].type == STAR) {
            return matchstar(pattern[0], &pattern[2], text, matchlength);
        } else if(pattern[1].type == PLUS) {
            return matchplus(pattern[0], &pattern[2], text, matchlength);
        } else if((pattern[0].type == END) && pattern[1].type == UNUSED) {
            return (text[0] == '\0');
        }
/*    Branching is not working properly
        else if (pattern[1].type == BRANCH)
        {
            return (matchpattern(pattern, text) || matchpattern(&pattern[2], text));
        }
*/
    (*matchlength)++;
    } while((text[0] != '\0') && matchone(*pattern++, *text++));

    *matchlength = pre;

    return 0;
}

#endif
