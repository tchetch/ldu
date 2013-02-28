/* Copyright (c) 2013 Etienne Bagnoud <etienne@lamaisondebarbie.ch>
 *
 * This source file is subject to MIT license bundled whith this package
 * in the file LICENSE.
 */
#ifndef LDAP_DEV_UTILS_H__
#define LDAP_DEV_UTILS_H__

#include <ldap.h>
#include "ldap_dev_utils_vendors.h" /* List of vendors */

#ifdef LDU_ALLOCATOR
#include LDU_ALLOCATOR
#else
#include "ldu_stdlib_alloc.h" 
#endif

#ifndef BER_BVISNULL
#define BER_BVISNULL(bv)			((bv)->bv_val == NULL)
#endif /* BER_BVISNULL */

#define LDU_FREE_LDAP_URI(x)	do { if((x)) { \
		if((x)->hostname) LDU_FREE((x)->hostname); \
		if((x)->uri) LDU_FREE((x)->uri); \
		LDU_FREE((x)); }\
	} while(0)

#define LDU_URI_TYPE_LDAP	0
#define LDU_URI_TYPE_LDAPS	1
#define LDU_URI_TYPE_LDAPI	2
#define LDU_URI_TYPE_CLDAP	3

#if LDU_MICROSOF_LDAP == 1 || LDU_ORACLE_LDAP == 1
#define LDAPS_PORT LDAP_SSL_PORT
#else
#define LDAP_SSL_PORT LDAPS_PORT
#endif

struct s_ldu_ldap_uri {
	char * uri;
	size_t uri_len;
	int type; /* 0 => ldap, 1 => ldaps, 2 => ldapi */
	char * hostname;
	int port;

	char * non_authority;
};

char * ldu_strdup(char * str);
struct berval * ldu_ber_dupbv(struct berval * dst, struct berval * src);

LDAPControl * ldu_ldap_control_create(const char * oid, int iscritical,
		struct berval * value);
void ldu_ldap_controls_free(LDAPControl ** ctrls);
void ldu_ldap_control_free(LDAPControl * ctrl);
struct s_ldu_ldap_uri * ldu_ldap_parse_uri(char * uri);
char * ldu_ldap_join_uri(struct s_ldu_ldap_uri * uri);
LDAP * ldu_ldap_initialize(char * host, int port);

#endif /* LDAP_DEV_UTILS_H__ */
