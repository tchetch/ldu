/* Copyright (c) 2013 Etienne Bagnoud <etienne@lamaisondebarbie.ch>
 *
 * This source file is subject to MIT license bundled whith this package
 * in the file LICENSE.
 */
#ifndef LDAP_DEV_UTILS_VENDORS_H__
#define LDAP_DEV_UTILS_VENDORS_H__

#define LDU_OPENLDAP_LDAP	0	
#define LDU_MICROSOFT_LDAP	0
#define LDU_NOVELL_LDAP		0
#define LDU_ORACLE_LDAP		0
#define LDU_MOZILLA_LDAP	0

#define LDU_HAS_CLDAP		0

#ifdef _LDAP_H /* Can be Novell or OpenLDAP */
#	ifdef LDAP_VENDOR_VERSION_PATCH /* OpenLDAP define this one */
#		undef LDU_OPENLDAP_LDAP
#		define LDU_OPENLDAP_LDAP 1
#		ifdef LDAP_CONNECTIONLESS
#			undef LDU_HAS_CLDAP
#			define LDU_HAS_CLDAP 1
#		endif
#	else
#		undef LDU_NOVELL_LDAP
#		define LDU_NOVELL_LDAP 1
#	endif
#else
#	ifdef LDAP_CLIENT_DEFINED /* Microsoft */
#		undef LDU_MICROSOFT_LDAP
#		define LDU_MICROSOFT_LDAP	1
#		undef LDU_HAS_CLDAP
#		define LDU_HAS_CLDAP	1
#	elif _LDAP_STANDARD_H /* Mozilla */
#		undef LDU_MOZILLA_LDAP
#		define LDU_MOZILLA_LDAP	1
#	elif GSLC_ORACLE /* Oracle */
#		undef LDU_ORACLE_LDAP
#		define LDU_ORACLE_LDAP	1
#	endif
#endif /* #ifdef _LDAP_H */

#endif /* #ifndef LDAP_DEV_UTILS_VENDORS_H__ */

