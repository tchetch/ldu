#ifndef LDU_ALLOC_H__
#define LDU_ALLOC_H__

#include "php.h"

#define LDU_MALLOC emalloc
#define LDU_CALLOC ecalloc
#define LDU_FREE free
#define LDU_STRDUP estrdup
#define LDU_REALLOC erealloc

#endif /* #ifndef LDU_ALLOC_H__ */
