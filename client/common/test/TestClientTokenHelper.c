/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Tests for the external Entra ID token helper
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <freerdp/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winpr/crt.h>
#include <winpr/string.h>
#include <winpr/sysinfo.h>

#if defined(WITH_TOKEN_HELPER) && !defined(_WIN32)

#include <unistd.h>

#include <freerdp/client.h>
#include <freerdp/settings.h>

#include "../token_helper.h"

static const char fake_helper[] = TEST_SOURCE_DIR "/fake-token-helper.sh";
static const char expected_token[] = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ0ZXN0In0.c2ln";

static void set_mode(const char* mode)
{
	if (mode)
		(void)setenv("FAKE_TOKEN_HELPER_MODE", mode, 1);
	else
		(void)unsetenv("FAKE_TOKEN_HELPER_MODE");
}

static const char* const avd_scopes[] = { "https://www.wvd.azure.us/.default", "openid", "profile",
	                                      "offline_access" };

static TokenHelperRequest default_request(void)
{
	TokenHelperRequest request = WINPR_C_ARRAY_INIT;

	request.authority = "login.microsoftonline.us";
	request.tenant = "00000000-1111-2222-3333-444444444444";
	request.clientId = "a85cf173-4192-42f8-81fa-777a763e6e2c";
	request.scopes = avd_scopes;
	request.scopeCount = ARRAYSIZE(avd_scopes);
	request.timeoutMs = 20000;
	return request;
}

static BOOL expect_status(const char* what, TokenHelperStatus actual, TokenHelperStatus expected)
{
	if (actual == expected)
		return TRUE;

	(void)fprintf(stderr, "%s: expected %s, got %s\n", what,
	              client_token_helper_status_string(expected),
	              client_token_helper_status_string(actual));
	return FALSE;
}

/** The token is captured verbatim and stripped of the whitespace around it. */
static BOOL test_capture_and_trim(void)
{
	const TokenHelperRequest request = default_request();
	char* token = nullptr;

	set_mode("ok");
	const TokenHelperStatus status = client_token_helper_acquire(fake_helper, &request, &token);
	if (!expect_status("capture", status, TOKEN_HELPER_OK))
		return FALSE;

	BOOL rc = TRUE;
	if (!token || (strcmp(token, expected_token) != 0))
	{
		(void)fprintf(stderr, "capture: unexpected token length %" PRIuz "\n",
		              token ? strlen(token) : 0);
		rc = FALSE;
	}

	free(token);
	return rc;
}

/** A helper that exits 0 without printing anything is a failure, not an empty token. */
static BOOL test_empty_output(void)
{
	const TokenHelperRequest request = default_request();
	char* token = nullptr;

	set_mode("empty");
	const TokenHelperStatus status = client_token_helper_acquire(fake_helper, &request, &token);
	free(token);
	return expect_status("empty", status, TOKEN_HELPER_EMPTY);
}

/** Every documented exit code maps to its own status, and falls back accordingly. */
static BOOL test_exit_codes(void)
{
	static const struct
	{
		const char* mode;
		TokenHelperStatus status;
		BOOL fallBack;
	} cases[] = { { "10", TOKEN_HELPER_INTERACTION_REQUIRED, TRUE },
		          { "20", TOKEN_HELPER_CANCELLED, FALSE },
		          { "30", TOKEN_HELPER_NO_ACCOUNT, TRUE },
		          { "40", TOKEN_HELPER_UNAVAILABLE, TRUE },
		          { "50", TOKEN_HELPER_SERVER_ERROR, FALSE },
		          { "64", TOKEN_HELPER_USAGE, TRUE },
		          { "70", TOKEN_HELPER_INTERNAL, TRUE },
		          { "99", TOKEN_HELPER_UNKNOWN, TRUE } };

	const TokenHelperRequest request = default_request();

	for (size_t x = 0; x < ARRAYSIZE(cases); x++)
	{
		char* token = nullptr;

		set_mode(cases[x].mode);
		const TokenHelperStatus status = client_token_helper_acquire(fake_helper, &request, &token);
		const BOOL leaked = (token != nullptr);
		free(token);

		if (!expect_status(cases[x].mode, status, cases[x].status))
			return FALSE;

		if (client_token_helper_should_fall_back(status) != cases[x].fallBack)
		{
			(void)fprintf(stderr, "%s: expected fall back %s\n", cases[x].mode,
			              cases[x].fallBack ? "TRUE" : "FALSE");
			return FALSE;
		}

		if (leaked)
		{
			(void)fprintf(stderr, "%s: a token was returned for a failure\n", cases[x].mode);
			return FALSE;
		}
	}

	return TRUE;
}

/** A helper that never answers is killed once the bound expires. */
static BOOL test_timeout(void)
{
	TokenHelperRequest request = default_request();
	char* token = nullptr;

	request.timeoutMs = 750;

	set_mode("hang");
	const UINT64 start = GetTickCount64();
	const TokenHelperStatus status = client_token_helper_acquire(fake_helper, &request, &token);
	const UINT64 elapsed = GetTickCount64() - start;
	free(token);

	if (!expect_status("timeout", status, TOKEN_HELPER_TIMEOUT))
		return FALSE;

	if (elapsed > 15000)
	{
		(void)fprintf(stderr, "timeout: waited %" PRIu64 " ms for a 750 ms bound\n", elapsed);
		return FALSE;
	}

	return TRUE;
}

/** @return the @p nth line of @p text, or @c nullptr. */
static char* nth_line(const char* text, size_t nth)
{
	const char* pos = text;

	for (size_t x = 0; x < nth; x++)
	{
		pos = strchr(pos, '\n');
		if (!pos)
			return nullptr;
		pos++;
	}

	const char* end = strchr(pos, '\n');
	const size_t len = end ? (size_t)(end - pos) : strlen(pos);
	return strndup(pos, len);
}

static BOOL expect_line(const char* argv, size_t nth, const char* expected)
{
	char* line = nth_line(argv, nth);
	const BOOL rc = line && (strcmp(line, expected) == 0);

	if (!rc)
		(void)fprintf(stderr, "argument %" PRIuz ": expected '%s', got '%s'\n", nth, expected,
		              line ? line : "(none)");
	free(line);
	return rc;
}

/** The command line follows docs/ENTRA-CLIENT-CLI.md: a host authority, a separate tenant,
 *  one decoded scope per option, and --req-cnf only for a proof of possession request. */
static BOOL test_argument_vector(void)
{
	TokenHelperRequest request = default_request();
	char* argv = nullptr;

	request.reqCnf = "eyJraWQiOiAiPGtleS1pZD4ifQ";
	request.prompt = "never";

	set_mode("argv");
	const TokenHelperStatus status = client_token_helper_acquire(fake_helper, &request, &argv);
	if (!expect_status("argv", status, TOKEN_HELPER_OK) || !argv)
	{
		free(argv);
		return FALSE;
	}

	const BOOL rc = expect_line(argv, 0, "token") && expect_line(argv, 1, "--authority") &&
	                expect_line(argv, 2, "login.microsoftonline.us") &&
	                expect_line(argv, 3, "--tenant") &&
	                expect_line(argv, 4, "00000000-1111-2222-3333-444444444444") &&
	                expect_line(argv, 5, "--client-id") &&
	                expect_line(argv, 6, "a85cf173-4192-42f8-81fa-777a763e6e2c") &&
	                expect_line(argv, 7, "--req-cnf") && expect_line(argv, 8, request.reqCnf) &&
	                expect_line(argv, 9, "--prompt") && expect_line(argv, 10, "never") &&
	                expect_line(argv, 11, "--scope") &&
	                expect_line(argv, 12, "https://www.wvd.azure.us/.default") &&
	                expect_line(argv, 13, "--scope") && expect_line(argv, 14, "openid") &&
	                expect_line(argv, 17, "--scope") && expect_line(argv, 18, "offline_access");

	free(argv);
	return rc;
}

/** The helper is selected by setting, then environment, and @c off keeps the browser flow. */
static BOOL test_resolve(void)
{
	rdpSettings* settings = freerdp_settings_new(0);
	if (!settings)
		return FALSE;

	BOOL rc = FALSE;
	char* resolved = nullptr;

	(void)setenv("FREERDP_TOKEN_HELPER", fake_helper, 1);

	resolved = client_token_helper_resolve(settings);
	if (!resolved || (strcmp(resolved, fake_helper) != 0))
	{
		(void)fprintf(stderr, "resolve: the environment was not honoured\n");
		goto out;
	}
	free(resolved);

	if (!freerdp_settings_set_string(settings, FreeRDP_TokenHelperPath, "off"))
		goto out;

	resolved = client_token_helper_resolve(settings);
	if (resolved)
	{
		(void)fprintf(stderr, "resolve: /token-helper:off did not disable the helper\n");
		goto out;
	}

	if (!freerdp_settings_set_string(settings, FreeRDP_TokenHelperPath,
	                                 "/nonexistent/entra-token-helper"))
		goto out;

	resolved = client_token_helper_resolve(settings);
	if (resolved)
	{
		(void)fprintf(stderr, "resolve: a missing binary was accepted\n");
		goto out;
	}

	if (!freerdp_settings_set_string(settings, FreeRDP_TokenHelperPath, fake_helper))
		goto out;

	resolved = client_token_helper_resolve(settings);
	if (!resolved || (strcmp(resolved, fake_helper) != 0))
	{
		(void)fprintf(stderr, "resolve: the setting did not win over the environment\n");
		goto out;
	}

	rc = TRUE;

out:
	free(resolved);
	(void)unsetenv("FREERDP_TOKEN_HELPER");
	freerdp_settings_free(settings);
	return rc;
}

static rdpContext* test_context_new(void)
{
	RDP_CLIENT_ENTRY_POINTS entry = WINPR_C_ARRAY_INIT;

	entry.Size = sizeof(entry);
	entry.Version = RDP_CLIENT_INTERFACE_VERSION;
	entry.ContextSize = sizeof(rdpClientContext);

	rdpContext* context = freerdp_client_context_new(&entry);
	if (!context)
		return nullptr;

	rdpSettings* settings = context->settings;
	if (!freerdp_settings_set_string(settings, FreeRDP_GatewayAzureActiveDirectory,
	                                 "login.microsoftonline.us") ||
	    !freerdp_settings_set_string(settings, FreeRDP_GatewayAvdClientID,
	                                 "a85cf173-4192-42f8-81fa-777a763e6e2c") ||
	    !freerdp_settings_set_string(settings, FreeRDP_GatewayAvdScope,
	                                 "https%3A%2F%2Fwww.wvd.azure.us%2F.default") ||
	    !freerdp_settings_set_string(settings, FreeRDP_TokenHelperPath, fake_helper))
	{
		freerdp_client_context_free(context);
		return nullptr;
	}

	return context;
}

/** Run @p type through the installed callback with stdout captured. */
static BOOL dispatch(rdpContext* context, AccessTokenType type, char** token, char** stdoutText,
                     BOOL* result)
{
	const char* tmpdir = getenv("TMPDIR");
	char* path = nullptr;
	size_t pathlen = 0;

	if (winpr_asprintf(&path, &pathlen, "%s/TestClientTokenHelper.XXXXXX",
	                   (tmpdir && (tmpdir[0] != '\0')) ? tmpdir : "/tmp") <= 0)
		return FALSE;

	const int file = mkstemp(path);
	if (file < 0)
	{
		free(path);
		return FALSE;
	}

	(void)fflush(stdout);
	const int saved = dup(STDOUT_FILENO);
	if ((saved < 0) || (dup2(file, STDOUT_FILENO) < 0))
	{
		close(file);
		(void)unlink(path);
		free(path);
		return FALSE;
	}

	*result = context->instance->GetAccessToken(context->instance, type, token, 0);

	(void)fflush(stdout);
	(void)dup2(saved, STDOUT_FILENO);
	close(saved);

	const off_t size = lseek(file, 0, SEEK_END);
	char* text = calloc((size > 0) ? (size_t)size + 1 : 1, sizeof(char));
	if (text && (size > 0))
	{
		(void)lseek(file, 0, SEEK_SET);
		const ssize_t got = read(file, text, (size_t)size);
		if (got > 0)
			text[got] = '\0';
	}

	close(file);
	(void)unlink(path);
	free(path);

	*stdoutText = text;
	return text != nullptr;
}

/** A successful helper answers on its own: the browser flow prints nothing. */
static BOOL test_no_browser_flow_on_success(void)
{
	rdpContext* context = test_context_new();
	if (!context)
		return FALSE;

	BOOL rc = FALSE;
	char* token = nullptr;
	char* text = nullptr;
	BOOL result = FALSE;

	if (context->instance->GetAccessToken != client_token_helper_get_access_token)
	{
		(void)fprintf(stderr, "the token helper is not the default GetAccessToken\n");
		goto out;
	}

	set_mode("ok");
	if (!dispatch(context, ACCESS_TOKEN_TYPE_AVD, &token, &text, &result))
		goto out;

	if (!result || !token || (strcmp(token, expected_token) != 0))
	{
		(void)fprintf(stderr, "the dispatcher did not return the helper's token\n");
		goto out;
	}

	if (strstr(text, "Browse to:"))
	{
		(void)fprintf(stderr, "the browser flow ran even though the helper succeeded\n");
		goto out;
	}

	free(token);
	free(text);
	token = nullptr;
	text = nullptr;

	/* A cancelled sign-in is an answer, so the browser flow must not ask again either. */
	set_mode("20");
	if (!dispatch(context, ACCESS_TOKEN_TYPE_AVD, &token, &text, &result))
		goto out;

	if (result || token)
	{
		(void)fprintf(stderr, "a cancelled sign-in produced a token\n");
		goto out;
	}

	if (strstr(text, "Browse to:"))
	{
		(void)fprintf(stderr, "the browser flow ran after the user cancelled\n");
		goto out;
	}

	rc = TRUE;

out:
	free(token);
	free(text);
	freerdp_client_context_free(context);
	return rc;
}

#endif /* WITH_TOKEN_HELPER && !_WIN32 */

int TestClientTokenHelper(int argc, char* argv[])
{
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);

#if !defined(WITH_TOKEN_HELPER) || defined(_WIN32)
	(void)fprintf(stderr, "Build does not support the token helper, skipping\n");
	return 0;
#else
	if (!test_resolve())
		return -1;
	if (!test_capture_and_trim())
		return -1;
	if (!test_empty_output())
		return -1;
	if (!test_exit_codes())
		return -1;
	if (!test_argument_vector())
		return -1;
	if (!test_timeout())
		return -1;
	if (!test_no_browser_flow_on_success())
		return -1;
	return 0;
#endif
}
