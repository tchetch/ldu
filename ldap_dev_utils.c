/* Copyright (c) 2013 Etienne Bagnoud <etienne@lamaisondebarbie.ch>
 *
 * This source file is subject to MIT license bundled whith this package
 * in the file LICENSE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ldap_dev_utils.h"

/* Duplicate string if not available */
char * ldu_strdup(char * str) 
{
	char * dup_str = NULL;
	size_t str_len = 0;

	str_len = strlen(str);
	if(str_len > 0) {
		dup_str = LDU_MALLOC(str_len + 1);
		if(dup_str != NULL) {
			memcpy(dup_str, str, str_len);
			*(dup_str + str_len) = '\0';
		}
	}

	return dup_str;
}

/* Duplicate src berval into dst berval. 
   This function should not be used outside this code, use ber_bvdup
   available on every API.
 */
struct berval * ldu_ber_dupbv(struct berval * dst, struct berval * src)
{
	struct berval * new = NULL;

	if(src != NULL) {
		if(dst == NULL) {
			new = LDU_MALLOC(sizeof(*dst));
		} else {
			new = dst;
		}
		if(new != NULL) {
			if(src->bv_val == NULL) {
				new->bv_val = NULL;
				new->bv_len = 0;
			} else {
				new->bv_val = LDU_MALLOC(src->bv_len + 1);
				if(new->bv_val == NULL) {
					if(dst == NULL) {
						LDU_FREE(new);
					}
					new = NULL;
				} else {
					memcpy(new->bv_val, src->bv_val, src->bv_len);
					new->bv_val[src->bv_len] = '\0';
					new->bv_len = src->bv_len;
				}
			}
		}
	}

	return new;
}

/* Create an LDAPControl */
LDAPControl * ldu_ldap_control_create(const char * oid, int iscritical,
		struct berval * value)
{
	LDAPControl * ctrl = NULL;

	if(oid != NULL) {
		ctrl = LDU_CALLOC(sizeof(*ctrl), 1);
		if(ctrl != NULL) {
			ctrl->ldctl_iscritical = iscritical ? 1 : 0;

			if(value != NULL && ! BER_BVISNULL(value)) {
				ldu_ber_dupbv( &(ctrl->ldctl_value), value);
			}

			ctrl->ldctl_oid = LDU_STRDUP(oid);
			if(ctrl->ldctl_oid == NULL) {
				ldu_ldap_control_free(ctrl);
				ctrl = NULL;
			}
		}
	}

	return ctrl;
}

void ldu_ldap_controls_free(LDAPControl ** ctrls)
{
	LDAPControl ** orig = ctrls;

	if(ctrls != NULL) {
		while(*ctrls != NULL) {
			ldu_ldap_control_free(*ctrls);
			ctrls++;
		}
		LDU_FREE(orig);
	}
}

void ldu_ldap_control_free(LDAPControl * ctrl)
{
	if(ctrl != NULL) {
		if(ctrl->ldctl_value.bv_val != NULL) {
			LDU_FREE(ctrl->ldctl_value.bv_val);
		}
		if(ctrl->ldctl_oid != NULL) {
			LDU_FREE(ctrl->ldctl_oid);
		}
	
		LDU_FREE(ctrl);
	}
}


/* parse an ldap uri */
#if LDU_OPENLDAP_LDAP == 0
struct s_ldu_ldap_uri * ldu_ldap_parse_uri(char * uri)
{
	char * strtol_end = NULL;
	char * tmp = NULL;
	char * uri_ori = uri;
	size_t uri_len = 0;
	struct s_ldu_ldap_uri * urip;
	
	if(uri == NULL) return NULL;

	urip = LDU_MALLOC(sizeof(*urip));
	if(urip != NULL) {
		
		urip->port = -1;
		urip->uri = NULL;
		urip->hostname = NULL;
		urip->uri_len = strlen(uri);
		uri_len = urip->uri_len;

		if( ! (uri_len > 0)) goto uri_looks_invalid;
		if(*uri == '\0') goto uri_looks_invalid;
		
		/* Keep a copy for us */
		urip->uri = LDU_STRDUP(uri);
		uri_ori = urip->uri; /* save uri ptr origin */

		if(uri_len >= 5 && strncmp(urip->uri, "ldaps", 5) == 0) {
			urip->type = LDU_URI_TYPE_LDAPS;
			urip->uri += 5;
			uri_len -= 5;
		} else if(uri_len >= 5 && strncmp(urip->uri, "ldapi", 5) == 0) {
			urip->type = LDU_URI_TYPE_LDAPI;
			urip->uri += 5;
			uri_len -= 5;

		} else if(uri_len >= 5 && strncmp(urip->uri, "cldap", 5) == 0) {
			urip->type = LDU_URI_TYPE_CLDAP;
			urip->uri += 5;
			uri_len -= 5;

		/* the smallest one, last check */
		} else if(uri_len >= 4 && strncmp(urip->uri, "ldap", 4) == 0) {
			urip->type = LDU_URI_TYPE_LDAP;
			urip->uri += 4;
			uri_len -= 4;
		} else {
			goto uri_looks_invalid;
		}
		if(uri_len < 3) goto uri_looks_invalid;

		if(! strncmp(urip->uri, "://", 3) == 0) {
			goto uri_looks_invalid;
		}
		urip->uri += 3;
		uri_len -= 3;
		if( ! (uri_len > 0)) goto uri_looks_invalid;

		/* remove the non authority part of the uri if available */
		tmp = strchr(urip->uri, '/');
		if(tmp != NULL) {
			if(*(tmp + 1) == '\0') {
				urip->non_authority = NULL;
			} else {
				urip->non_authority = tmp + 1;
			}
			*tmp = '\0';
		} else {
			urip->non_authority = NULL;
		}
	
		/* is there any port */
		tmp = strchr(urip->uri, ':');
		if(tmp != NULL) {
			*tmp = '\0';
			urip->hostname = LDU_STRDUP(urip->uri);
			*tmp = ':';
			tmp++;

			urip->port = strtol(tmp, &strtol_end, 10);
			if(*strtol_end != '\0') {
				goto uri_looks_invalid;	
			}
		} else {
			urip->hostname = LDU_STRDUP(urip->uri);
		}

		urip->uri = uri_ori;

		if(urip->port == -1) {
			switch(urip->type) {
				case LDU_URI_TYPE_LDAP:
					urip->port = LDAP_PORT;
					break;
				case LDU_URI_TYPE_LDAPS:
					urip->port = LDAPS_PORT;
					break;
			}
		}
	}

	return urip;

uri_looks_invalid:
	urip->uri = uri_ori;
	LDU_FREE_LDAP_URI(urip);
	return NULL;
}
#else
/* With OpenLDAP we have a parsing function, use it */
struct s_ldu_ldap_uri * ldu_ldap_parse_uri(char * uri) 
{
	struct s_ldu_ldap_uri * ldu_uri = NULL;
	LDAPURLDesc * urip = NULL;

	if(ldap_url_parse(uri, &urip) == 0) {
		ldu_uri = LDU_MALLOC(sizeof(*ldu_uri));
		if(ldu_uri != NULL) {
			if(strcmp("ldaps", urip->lud_scheme) == 0) {
				ldu_uri->type = LDU_URI_TYPE_LDAPS;
			} else if(strcmp("ldapi", urip->lud_scheme) == 0) {
				ldu_uri->type = LDU_URI_TYPE_LDAPI;
			} else if(strcmp("cldap", urip->lud_scheme) == 0) {
				ldu_uri->type = LDU_URI_TYPE_CLDAP;
			} else if(strcmp("ldap", urip->lud_scheme) == 0) {
				ldu_uri->type = LDU_URI_TYPE_LDAP;
			} else {
				LDU_FREE(ldu_uri);
				ldu_uri = NULL;
			}
			
			if(ldu_uri != NULL) {
				ldu_uri->hostname = LDU_STRDUP(urip->lud_host);
				ldu_uri->port = urip->lud_port;
				ldu_uri->non_authority = NULL;
			}
		}

		ldap_free_urldesc(urip);
	}

	return ldu_uri;
}
#endif

/* Create a URL that can be passed to OpenLDAP ldap_initialize (non-authority
   part must not be added as ldap_initialize behavior is undefined in that
   case).
 */
char * ldu_ldap_join_uri(struct s_ldu_ldap_uri * uri)
{
	char * uri_str = NULL;
	size_t uri_len = 0;
	char port[7] = { '\0' };

	if(uri != NULL) {
		if(uri->type == LDU_URI_TYPE_LDAP) {
			uri_len += 4;
		} else {
			uri_len += 5;
		}

		uri_len += 3;
		uri_len = strlen(uri->hostname);

		if(uri->port > 0) {
			uri_len += 6; /* port is, at max, ":XXXXX" */
		}

		uri_len += 2; /* add '/' and '\0' */

		uri_str = LDU_MALLOC(uri_len + 1);
		if(uri_str != NULL) {
			*uri_str = '\0';
			switch(uri->type) {
				case LDU_URI_TYPE_LDAP:
					strncat(uri_str, "ldap", 4);
					break;
				case LDU_URI_TYPE_LDAPS:
					strncat(uri_str, "ldaps", 5);
					break;
				case LDU_URI_TYPE_CLDAP:
					strncat(uri_str, "cldap", 5);
				case LDU_URI_TYPE_LDAPI:
					strncat(uri_str, "ldapi", 5);
					break;
			}
			strncat(uri_str, "://", 3);
			strncat(uri_str, uri->hostname, strlen(uri->hostname));
			
			if(uri->port > 0 ) {
				snprintf(port, 7, ":%d", uri->port);
				port[6] = '\0';
				strncat(uri_str, port, 6);
			}
			strncat(uri_str, "/", 1);
		}
	}

	return uri_str;
}

LDAP * ldu_ldap_initialize(char * host, int port)
{
	LDAP * link = NULL;
	char * tmp = NULL;
	struct s_ldu_ldap_uri * uri = NULL;

	uri = ldu_ldap_parse_uri(host);
	if(uri == NULL) {
		uri = LDU_MALLOC(sizeof(*uri));
		if(uri != NULL) {
			uri->hostname = LDU_STRDUP(host);
			tmp = strchr(uri->hostname, ':');
			if(tmp == NULL) {
				if(port > 0) {
					uri->port = port;
				} else {
					uri->port = LDAP_PORT;
				}
				uri->type = LDU_URI_TYPE_LDAP;
			} else {
				*tmp = '\0';
				tmp++;
				if(port > 0) {
					uri->port = port;
				} else {
					uri->port = strtol(tmp, NULL, 10);
					if(uri->port <= 0) {
						uri->port = LDAP_PORT;
					}	
				}
				uri->type = LDU_URI_TYPE_LDAP;
			}
		}
	}


#if LDU_HAS_CLDAP == 0
	if(uri->type == LDU_URI_TYPE_CLDAP) {
		link = NULL;
		goto clean_up_and_return;
	}
#endif

#if LDU_OPENLDAP_LDAP == 1
	tmp = ldu_ldap_join_uri(uri);
	if(tmp != NULL) {
		/* takes care of everything */
		if(ldap_initialize(&link, tmp) != LDAP_SUCCESS) {
			link = NULL; /* no need to free */
		}
	}
	LDU_FREE(tmp);
	goto clean_up_and_return;
#else
	/* Assume only openldap support ldapi:// */
	if(uri->type == LDU_URI_TYPE_LDAPI) {
		link = NULL;
		goto clean_up_and_return;
	} else if(uri->type == LDU_URI_TYPE_CLDAP) {
#if LDU_MICROSOFT_LDAP
		link = cldap_open(uri->hostname, uri->port); /* ret NULL in case of
														failure
													  */
		goto clean_up_and_return;
#else
		link = NULL;
		goto clean_up_and_return;
#endif /* LDU_MICROSOFT */
	} else if(uri->type == LDAP_URI_TYPE_LDAP) {
		/* All API support ldap_init */
		link = ldap_init(uri->hostname, uri->port);
		goto clean_up_and_return;
	}
#endif /* LDU_OPENLDAP */

clean_up_and_return:
	LDU_FREE_LDAP_URI(uri);
	return link;
}
