/*
 * Copyright (C) 2014 - David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <auth.h>
#include <context.h>

#include <tap/tap.h>
#include <utils.h>

#define NUM_TESTS 3

static void test_auth_new(void)
{
	struct context ctx;
	OtrlAuthInfo *auth = &ctx.auth;

	/* API call. */
	otrl_auth_new(&ctx);

	ok(auth->authstate == OTRL_AUTHSTATE_NONE &&
		auth->our_keyid == 0 &&
		auth->encgx == NULL &&
		auth->encgx_len == 0 &&
		utils_is_zeroed(auth->r, 16) &&
		utils_is_zeroed(auth->hashgx, 32) &&
		auth->their_pub == NULL &&
		auth->their_keyid == 0 &&
		auth->enc_c == NULL &&
		auth->enc_cp == NULL &&
		auth->mac_m1 == NULL &&
		auth->mac_m1p == NULL &&
		auth->mac_m2 == NULL &&
		auth->mac_m2p == NULL &&
		utils_is_zeroed(auth->their_fingerprint, 20) &&
		auth->initiated == 0 &&
		auth->protocol_version == 0 &&
		utils_is_zeroed(auth->secure_session_id, 20) &&
		auth->secure_session_id_len == 0 &&
		auth->lastauthmsg == NULL &&
		auth->commit_sent_time == 0 &&
		auth->context == &ctx,
		"OTR auth info init is valid");
}

static void test_auth_clear(void)
{
	struct context ctx;
	OtrlAuthInfo *auth = &ctx.auth;

	/* API call. */
	otrl_auth_clear(auth);

	ok(auth->authstate == OTRL_AUTHSTATE_NONE &&
		auth->our_keyid == 0 &&
		auth->encgx == NULL &&
		auth->encgx_len == 0 &&
		utils_is_zeroed(auth->r, 16) &&
		utils_is_zeroed(auth->hashgx, 32) &&
		auth->their_pub == NULL &&
		auth->their_keyid == 0 &&
		auth->enc_c == NULL &&
		auth->enc_cp == NULL &&
		auth->mac_m1 == NULL &&
		auth->mac_m1p == NULL &&
		auth->mac_m2 == NULL &&
		auth->mac_m2p == NULL &&
		utils_is_zeroed(auth->their_fingerprint, 20) &&
		auth->initiated == 0 &&
		auth->protocol_version == 0 &&
		utils_is_zeroed(auth->secure_session_id, 20) &&
		auth->secure_session_id_len == 0 &&
		auth->lastauthmsg == NULL &&
		auth->commit_sent_time == 0 &&
		auth->context == &ctx,
		"OTR auth info clear is valid");
}

static void test_auth_start_v23(void)
{
	unsigned int version = 3;
	gcry_error_t err;
	struct context ctx;
	OtrlAuthInfo *auth = &ctx.auth;

	/* API call. */
	otrl_auth_new(&ctx);
	err = otrl_auth_start_v23(auth, version);

	ok(err == gcry_error(GPG_ERR_NO_ERROR) &&
		auth->initiated == 1 &&
		auth->protocol_version == version &&
		auth->context->protocol_version == version &&
		auth->our_keyid == 1 &&
		!utils_is_zeroed(auth->r, sizeof(auth->r)) &&
		auth->encgx != NULL &&
		auth->encgx_len > 0 &&
		!utils_is_zeroed(auth->hashgx, sizeof(auth->hashgx)) &&
		auth->lastauthmsg != NULL &&
		auth->authstate == OTRL_AUTHSTATE_AWAITING_DHKEY,
		"OTR auth start v23 is valid");
}

int main(int argc, char **argv)
{
	/* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS);

	/* Initialize libotr. */
	otrl_dh_init();

	test_auth_new();
	test_auth_clear();
	test_auth_start_v23();

	return 0;
}
