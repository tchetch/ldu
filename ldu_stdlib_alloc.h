#ifndef LDU_ALLOC_H__
#define LDU_ALLOC_H__

#include <stdlib.h>

#define	LDU_MALLOC	malloc
#define LDU_CALLOC	calloc
#define LDU_FREE	free
#if _SVID_SOURCE || _BSD_SOURCE || _XOPEN_SOURCE >= 500 || _XOPEN_SOURCE && _XOPEN_SOURCE_EXTENDED || _POSIX_C_SOURCE >= 200809
#define	LDU_STRDUP	strdup
#else
#define LDU_STRDUP	ldu_strdup
#endif
#define LDU_REALLOC realloc

#endif /* #ifndef LDU_ALLOC_H__ */
