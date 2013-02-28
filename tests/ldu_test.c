/* Copyright (c) 2013 Etienne Bagnoud <etienne@lamaisondebarbie.ch>
 *
 * This source file is subject to MIT license bundled whith this package
 * in the file LICENSE.
 */
#include <ldap_dev_utils.h>
#include <check.h>

START_TEST(t_ldu_ber_dupbv1) 
{
	/* test with NULL parameters */
	fail_unless(ldu_ber_dupbv(NULL, NULL) == NULL,
			"NULL parameters must return NULL");
}
END_TEST

START_TEST(t_ldu_ber_dupbv2)
{
	struct berval * dst = NULL;
	struct berval * src = NULL;
	
	/* test with empty source berval */
	src = calloc(sizeof(*src), 0);
	dst = ldu_ber_dupbv(NULL, src);
	fail_if(dst == NULL, "Empty source must return valid pointer");
	fail_unless(dst->bv_val == NULL &&
			dst->bv_len == 0, "Empty source must return empty berval");
	LDU_FREE(dst);
	LDU_FREE(src);
}
END_TEST

START_TEST(t_ldu_ldap_parse_uri1)
{
	/* NULL parameter test */
	fail_if(ldu_ldap_parse_uri(NULL) != NULL,
			"Must not return valid pointer for NULL param");
}
END_TEST

START_TEST(t_ldu_ldap_parse_uri2)
{
	struct s_ldu_ldap_uri * uri = NULL;
	char * uri_str = NULL;

	/* Simple URI */
	uri = ldu_ldap_parse_uri("ldap://localhost");
	fail_if(uri == NULL, "Valid URI must return valid pointer");
	fail_if(uri->type != LDU_URI_TYPE_LDAP, 
			"URI is ldap://");
	fail_if(strcmp(uri->hostname, "localhost") != 0,
			"Hostname not parsed correctly");

	uri_str = ldu_ldap_join_uri(uri);
	fail_if(strcmp(uri_str, "ldap://localhost:389/") != 0,
		"Reconstruction of URI failed with \"%s\"", uri_str);	
	LDU_FREE(uri_str);
	
	LDU_FREE_LDAP_URI(uri);
}
END_TEST

START_TEST(t_ldu_ldap_parse_uri3)
{
	struct s_ldu_ldap_uri * uri = NULL;
	char * uri_str = NULL;
	
	/* More complex URI */
	uri = ldu_ldap_parse_uri("ldaps://test.example.com:678");
	fail_if(uri == NULL, "Valid URI must return valid pointer");
	fail_if(uri->type != LDU_URI_TYPE_LDAPS, 
			"URI is ldaps://");
	fail_if(strcmp(uri->hostname, "test.example.com") != 0,
			"Hostname not parsed correctly (\"%s\")", uri->hostname);
	fail_if(uri->port != 678, "Port not parsed correctly (%d)", uri->port);

	uri_str = ldu_ldap_join_uri(uri);
	fail_if(strcmp(uri_str, "ldaps://test.example.com:678/") != 0,
		"Reconstruction of URI failed with \"%s\"", uri_str);	
	LDU_FREE(uri_str);

	LDU_FREE_LDAP_URI(uri);

}
END_TEST

START_TEST(t_ldu_ldap_parse_uri4)
{
	struct s_ldu_ldap_uri * uri = NULL;
	char * uri_str = NULL;

	uri = ldu_ldap_parse_uri("ldap://test.example.com:8090/cn=test,dc=example,dc=com");
	fail_if(uri == NULL, "Valid URI must return valid pointer");
	fail_if(uri->type != LDU_URI_TYPE_LDAP,
			"URI is ldap://");
	fail_if(strcmp(uri->hostname, "test.example.com") != 0,
			"Hostname not parsed correctly (\"%s\")", uri->hostname);
	fail_if(uri->port != 8090,
			"Port not parsed correctly (%d)", uri->port);
	if(LDU_OPENLDAP_LDAP) {
		fail_if(uri->non_authority != NULL,
				"Non authorithy part is not parsed with OpenLDAP");
	} else {
		fail_if(strcmp(uri->non_authority, "cn=test,dc=example,dc=com") != 0,
				"Non-authority part not parsed correctly (\"%s\")", uri->non_authority);
	}
	
	uri_str = ldu_ldap_join_uri(uri);
	fail_if(strcmp(uri_str, "ldap://test.example.com:8090/") != 0,
		"Reconstruction of URI failed with \"%s\"", uri_str);	
	LDU_FREE(uri_str);
	
	LDU_FREE_LDAP_URI(uri);
}
END_TEST

START_TEST(t_ldu_ldap_parse_uri5)
{
	fail_if(ldu_ldap_parse_uri("xxx://xxxx:///") != NULL,
			"Invalid URI must return NULL");
}
END_TEST

START_TEST(t_ldu_ldap_parse_uri6)
{
	struct s_ldu_ldap_uri * uri = NULL;
	char * uri_str = NULL;

	uri = ldu_ldap_parse_uri("ldaps://test.example.com:60000/cn=test,dc=example,dc=com");
	fail_if(uri == NULL, "Valid URI must return valid pointer");
	fail_if(uri->type != LDU_URI_TYPE_LDAPS,
			"URI is ldap://");
	fail_if(strcmp(uri->hostname, "test.example.com") != 0,
			"Hostname not parsed correctly (\"%s\")", uri->hostname);
	fail_if(uri->port != 60000,
			"Port not parsed correctly (%d)", uri->port);
	if(LDU_OPENLDAP_LDAP) {
		fail_if(uri->non_authority != NULL,
				"Non authorithy part is not parsed with OpenLDAP");
	} else {
		fail_if(strcmp(uri->non_authority, "cn=test,dc=example,dc=com") != 0,
				"Non-authority part not parsed correctly (\"%s\")", uri->non_authority);
	}
	
	uri_str = ldu_ldap_join_uri(uri);
	fail_if(strcmp(uri_str, "ldaps://test.example.com:60000/") != 0,
		"Reconstruction of URI failed with \"%s\"", uri_str);	
	LDU_FREE(uri_str);
	
	LDU_FREE_LDAP_URI(uri);
}
END_TEST

START_TEST(t_ldu_strdup1)
{
	char * sstr = "test string :)";
	char * dstr = NULL;

	dstr = ldu_strdup(sstr);
	fail_if(dstr == NULL, 
			"Destination string should be allocated and have a valide pointer "
			"value");
	if(dstr != NULL) { /* avoid segfault here */
		fail_if(strcmp(dstr, sstr) != 0,
				"String is corrupted during duplication");
	}

	LDU_FREE(dstr);
}
END_TEST

Suite * ldu_test_suite(void)
{
	Suite * s = suite_create("LDAP Dev Utils");
	TCase * tc_ber = tcase_create("BER Functions");
	TCase * tc_str = tcase_create("LDU String Manipulation");
	TCase * tc_ldap_uri = tcase_create("LDAP URI Manipulation");

	tcase_add_test(tc_ber, t_ldu_ber_dupbv1);
	tcase_add_test(tc_ber, t_ldu_ber_dupbv2);

	tcase_add_test(tc_ldap_uri, t_ldu_ldap_parse_uri1);
	tcase_add_test(tc_ldap_uri, t_ldu_ldap_parse_uri2);
	tcase_add_test(tc_ldap_uri, t_ldu_ldap_parse_uri3);
	tcase_add_test(tc_ldap_uri, t_ldu_ldap_parse_uri4);
	tcase_add_test(tc_ldap_uri, t_ldu_ldap_parse_uri5);
	tcase_add_test(tc_ldap_uri, t_ldu_ldap_parse_uri6);

	tcase_add_test(tc_str, t_ldu_strdup1);

	suite_add_tcase(s, tc_ber);
	suite_add_tcase(s, tc_ldap_uri);
	suite_add_tcase(s, tc_str);

	return s;
}

int main(int argc, char ** argv)
{
	int i = 0;
	int num_failed = 0;
	Suite * s = ldu_test_suite();
	SRunner * sr = srunner_create(s);
	int verbosity = CK_NORMAL;

	if(argc > 1) {
		for(i = 1; i < argc; i++) {
			if(strcmp(argv[i], "-v") == 0) {
				verbosity = CK_VERBOSE;
			}
		}
	}
	
	srunner_run_all(sr, verbosity);
	num_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (num_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
