/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * External Entra ID token helper
 *
 * Copyright 2026 Stephen J. Trotter <stephen.j.trotter@gmail.com>
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

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <winpr/crt.h>
#include <winpr/string.h>
#include <winpr/sysinfo.h>

#include <freerdp/client.h>
#include <freerdp/settings.h>

#include "token_helper.h"

#include <freerdp/log.h>
#define TAG CLIENT_TAG("common.token-helper")

#if !defined(_WIN32)
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define TOKEN_HELPER_DEFAULT_BINARY "entra-token-helper"
#define TOKEN_HELPER_OFF "off"
#define TOKEN_HELPER_MAX_OUTPUT (256UL * 1024UL)

const char* client_token_helper_status_string(TokenHelperStatus status)
{
	switch (status)
	{
		case TOKEN_HELPER_OK:
			return "ok";
		case TOKEN_HELPER_INTERACTION_REQUIRED:
			return "interaction-required";
		case TOKEN_HELPER_CANCELLED:
			return "cancelled";
		case TOKEN_HELPER_NO_ACCOUNT:
			return "no-account";
		case TOKEN_HELPER_UNAVAILABLE:
			return "unavailable";
		case TOKEN_HELPER_SERVER_ERROR:
			return "server-error";
		case TOKEN_HELPER_USAGE:
			return "usage";
		case TOKEN_HELPER_INTERNAL:
			return "internal";
		case TOKEN_HELPER_NO_HELPER:
			return "no-helper";
		case TOKEN_HELPER_SPAWN_FAILED:
			return "spawn-failed";
		case TOKEN_HELPER_TIMEOUT:
			return "timeout";
		case TOKEN_HELPER_EMPTY:
			return "empty-output";
		case TOKEN_HELPER_UNKNOWN:
		default:
			return "unknown";
	}
}

static TokenHelperStatus token_helper_status_from_exit(int code)
{
	switch (code)
	{
		case 0:
			return TOKEN_HELPER_OK;
		case 10:
			return TOKEN_HELPER_INTERACTION_REQUIRED;
		case 20:
			return TOKEN_HELPER_CANCELLED;
		case 30:
			return TOKEN_HELPER_NO_ACCOUNT;
		case 40:
			return TOKEN_HELPER_UNAVAILABLE;
		case 50:
			return TOKEN_HELPER_SERVER_ERROR;
		case 64:
			return TOKEN_HELPER_USAGE;
		case 70:
			return TOKEN_HELPER_INTERNAL;
		case 127:
			return TOKEN_HELPER_SPAWN_FAILED;
		default:
			return TOKEN_HELPER_UNKNOWN;
	}
}

static BOOL token_helper_is_space(char c)
{
	return (c == ' ') || (c == '\t') || (c == '\r') || (c == '\n') || (c == '\v') || (c == '\f');
}

/** Trim leading and trailing whitespace of @p buffer in place. */
static char* token_helper_trim(char* buffer)
{
	if (!buffer)
		return nullptr;

	char* start = buffer;
	while (*start && token_helper_is_space(*start))
		start++;

	size_t len = strlen(start);
	while ((len > 0) && token_helper_is_space(start[len - 1]))
		len--;
	start[len] = '\0';
	return start;
}

/** A growable @c nullptr terminated vector of owned strings. */
typedef struct
{
	char** items;
	size_t count;
	size_t capacity;
} TokenHelperArgv;

static void token_helper_argv_free(TokenHelperArgv* argv)
{
	if (!argv)
		return;

	for (size_t x = 0; x < argv->count; x++)
		free(argv->items[x]);
	free(argv->items);
	argv->items = nullptr;
	argv->count = 0;
	argv->capacity = 0;
}

static BOOL token_helper_argv_add(TokenHelperArgv* argv, const char* value)
{
	WINPR_ASSERT(argv);
	WINPR_ASSERT(value);

	if (argv->count + 2 > argv->capacity)
	{
		const size_t capacity = (argv->capacity == 0) ? 16 : argv->capacity * 2;
		char** items = realloc(argv->items, capacity * sizeof(char*));
		if (!items)
			return FALSE;
		argv->items = items;
		argv->capacity = capacity;
	}

	char* copy = _strdup(value);
	if (!copy)
		return FALSE;

	argv->items[argv->count++] = copy;
	argv->items[argv->count] = nullptr;
	return TRUE;
}

static BOOL token_helper_argv_add_option(TokenHelperArgv* argv, const char* name, const char* value)
{
	if (!value || (value[0] == '\0'))
		return TRUE;
	if (!token_helper_argv_add(argv, name))
		return FALSE;
	return token_helper_argv_add(argv, value);
}

static BOOL token_helper_is_executable(const char* path)
{
#if defined(_WIN32)
	WINPR_UNUSED(path);
	return FALSE;
#else
	struct stat st = WINPR_C_ARRAY_INIT;
	if (stat(path, &st) != 0)
		return FALSE;
	if (!S_ISREG(st.st_mode))
		return FALSE;
	return access(path, X_OK) == 0;
#endif
}

/** Look @p name up in @c PATH. */
static char* token_helper_search_path(const char* name)
{
	const char* path = getenv("PATH");
	if (!path || (path[0] == '\0'))
		return nullptr;

	char* copy = _strdup(path);
	if (!copy)
		return nullptr;

	char* result = nullptr;
	char* state = nullptr;
	for (char* dir = strtok_s(copy, ":", &state); dir; dir = strtok_s(nullptr, ":", &state))
	{
		if (dir[0] == '\0')
			continue;

		char* candidate = nullptr;
		size_t len = 0;
		if (winpr_asprintf(&candidate, &len, "%s/%s", dir, name) <= 0)
			continue;

		if (token_helper_is_executable(candidate))
		{
			result = candidate;
			break;
		}
		free(candidate);
	}

	free(copy);
	return result;
}

char* client_token_helper_resolve(const rdpSettings* settings)
{
	const char* configured = nullptr;

	if (settings)
		configured = freerdp_settings_get_string(settings, FreeRDP_TokenHelperPath);
	if (!configured || (configured[0] == '\0'))
		configured = getenv("FREERDP_TOKEN_HELPER");
	if (!configured || (configured[0] == '\0'))
		configured = TOKEN_HELPER_DEFAULT_BINARY;

	if (_stricmp(configured, TOKEN_HELPER_OFF) == 0)
		return nullptr;

	if (strchr(configured, '/'))
	{
		if (!token_helper_is_executable(configured))
		{
			WLog_WARN(TAG, "token helper '%s' is not an executable file", configured);
			return nullptr;
		}
		return _strdup(configured);
	}

	char* found = token_helper_search_path(configured);
	if (!found)
		WLog_DBG(TAG, "token helper '%s' not found in PATH", configured);
	return found;
}

#if !defined(_WIN32)
static void token_helper_free_secret(char* str, size_t len)
{
	if (str)
		SecureZeroMemory(str, len);
	free(str);
}

/** Read @p fd to EOF, bounded by @p timeoutMs and @ref TOKEN_HELPER_MAX_OUTPUT. */
static BOOL token_helper_drain(int fd, UINT32 timeoutMs, char** out, size_t* outlen, BOOL* timedOut)
{
	WINPR_ASSERT(out);
	WINPR_ASSERT(outlen);
	WINPR_ASSERT(timedOut);

	*out = nullptr;
	*outlen = 0;
	*timedOut = FALSE;

	size_t capacity = 4096;
	size_t used = 0;
	char* buffer = calloc(capacity, sizeof(char));
	if (!buffer)
		return FALSE;

	const UINT64 deadline = GetTickCount64() + timeoutMs;

	for (;;)
	{
		const UINT64 now = GetTickCount64();
		if (now >= deadline)
		{
			*timedOut = TRUE;
			goto fail;
		}

		struct pollfd pfd = WINPR_C_ARRAY_INIT;
		pfd.fd = fd;
		pfd.events = POLLIN;

		const UINT64 remain = deadline - now;
		const int ready = poll(&pfd, 1, (remain > INT32_MAX) ? INT32_MAX : (int)remain);
		if (ready < 0)
		{
			if (errno == EINTR)
				continue;
			goto fail;
		}
		if (ready == 0)
		{
			*timedOut = TRUE;
			goto fail;
		}

		if (used + 1 >= capacity)
		{
			if (capacity >= TOKEN_HELPER_MAX_OUTPUT)
			{
				WLog_ERR(TAG, "token helper produced more than %" PRIuz " bytes, aborting",
				         (size_t)TOKEN_HELPER_MAX_OUTPUT);
				goto fail;
			}

			const size_t next = capacity * 2;
			char* grown = calloc(next, sizeof(char));
			if (!grown)
				goto fail;
			memcpy(grown, buffer, used);
			token_helper_free_secret(buffer, capacity);
			buffer = grown;
			capacity = next;
		}

		const ssize_t got = read(fd, &buffer[used], capacity - used - 1);
		if (got < 0)
		{
			if ((errno == EINTR) || (errno == EAGAIN))
				continue;
			goto fail;
		}
		if (got == 0)
			break;

		used += (size_t)got;
	}

	buffer[used] = '\0';
	*out = buffer;
	*outlen = capacity;
	return TRUE;

fail:
	token_helper_free_secret(buffer, capacity);
	return FALSE;
}

static TokenHelperStatus token_helper_run(const char* binary, char* const* argv, UINT32 timeoutMs,
                                          char** token)
{
	int fds[2] = { -1, -1 };
	if (pipe(fds) != 0)
	{
		WLog_ERR(TAG, "pipe() failed with %s", strerror(errno));
		return TOKEN_HELPER_SPAWN_FAILED;
	}

	const pid_t pid = fork();
	if (pid < 0)
	{
		WLog_ERR(TAG, "fork() failed with %s", strerror(errno));
		close(fds[0]);
		close(fds[1]);
		return TOKEN_HELPER_SPAWN_FAILED;
	}

	if (pid == 0)
	{
		close(fds[0]);
		if (dup2(fds[1], STDOUT_FILENO) < 0)
			_exit(127);
		close(fds[1]);
		execv(binary, argv);
		_exit(127);
	}

	close(fds[1]);

	char* output = nullptr;
	size_t outlen = 0;
	BOOL timedOut = FALSE;
	const BOOL drained = token_helper_drain(fds[0], timeoutMs, &output, &outlen, &timedOut);
	close(fds[0]);

	if (timedOut)
	{
		WLog_ERR(TAG, "token helper did not answer within %" PRIu32 " ms, terminating it",
		         timeoutMs);
		(void)kill(pid, SIGKILL);
	}

	int wstatus = 0;
	pid_t waited = 0;
	do
	{
		waited = waitpid(pid, &wstatus, 0);
	} while ((waited < 0) && (errno == EINTR));

	if (timedOut)
		return TOKEN_HELPER_TIMEOUT;

	if (!drained || (waited < 0))
	{
		token_helper_free_secret(output, outlen);
		return TOKEN_HELPER_SPAWN_FAILED;
	}

	if (!WIFEXITED(wstatus))
	{
		WLog_ERR(TAG, "token helper terminated abnormally");
		token_helper_free_secret(output, outlen);
		return TOKEN_HELPER_SPAWN_FAILED;
	}

	TokenHelperStatus status = token_helper_status_from_exit(WEXITSTATUS(wstatus));
	if (status == TOKEN_HELPER_OK)
	{
		const char* trimmed = token_helper_trim(output);
		if (!trimmed || (trimmed[0] == '\0'))
			status = TOKEN_HELPER_EMPTY;
		else
		{
			char* result = _strdup(trimmed);
			if (!result)
				status = TOKEN_HELPER_SPAWN_FAILED;
			else
				*token = result;
		}
	}

	token_helper_free_secret(output, outlen);
	return status;
}
#endif

TokenHelperStatus client_token_helper_acquire(const char* binary, const TokenHelperRequest* request,
                                              char** token)
{
	if (!binary || !request || !token)
		return TOKEN_HELPER_USAGE;

	*token = nullptr;

#if defined(_WIN32)
	WLog_ERR(TAG, "the token helper is not supported on this platform");
	return TOKEN_HELPER_NO_HELPER;
#else
	if (!request->authority || (request->scopeCount == 0))
		return TOKEN_HELPER_USAGE;

	TokenHelperArgv argv = WINPR_C_ARRAY_INIT;
	TokenHelperStatus status = TOKEN_HELPER_SPAWN_FAILED;
	const UINT32 timeout =
	    (request->timeoutMs > 0) ? request->timeoutMs : TOKEN_HELPER_DEFAULT_TIMEOUT_MS;

	if (!token_helper_argv_add(&argv, binary) || !token_helper_argv_add(&argv, "token") ||
	    !token_helper_argv_add_option(&argv, "--authority", request->authority) ||
	    !token_helper_argv_add_option(&argv, "--tenant", request->tenant) ||
	    !token_helper_argv_add_option(&argv, "--client-id", request->clientId) ||
	    !token_helper_argv_add_option(&argv, "--req-cnf", request->reqCnf) ||
	    !token_helper_argv_add_option(&argv, "--prompt", request->prompt))
		goto out;

	for (size_t x = 0; x < request->scopeCount; x++)
	{
		if (!token_helper_argv_add_option(&argv, "--scope", request->scopes[x]))
			goto out;
	}

	/* The confirmation object binds a token to a private key and is never logged; neither is
	 * anything the helper writes to stdout. */
	WLog_DBG(TAG,
	         "running %s token --authority %s --tenant %s --client-id %s (%" PRIuz " scopes, %s)",
	         binary, request->authority, request->tenant ? request->tenant : "-",
	         request->clientId ? request->clientId : "-", request->scopeCount,
	         request->reqCnf ? "pop" : "bearer");

	status = token_helper_run(binary, argv.items, timeout, token);

out:
	token_helper_argv_free(&argv);
	return status;
#endif
}

/** Split @p scope, which arrives percent encoded and space separated, into decoded scopes. */
static BOOL token_helper_split_scope(const char* scope, TokenHelperArgv* out)
{
	WINPR_ASSERT(out);

	if (!scope || (scope[0] == '\0'))
		return TRUE;

	char* decoded = winpr_str_url_decode(scope, strlen(scope));
	if (!decoded)
		return FALSE;

	BOOL rc = TRUE;
	char* state = nullptr;
	for (char* item = strtok_s(decoded, " \t", &state); item;
	     item = strtok_s(nullptr, " \t", &state))
	{
		if (item[0] == '\0')
			continue;
		if (!token_helper_argv_add(out, item))
		{
			rc = FALSE;
			break;
		}
	}

	free(decoded);
	return rc;
}

static BOOL token_helper_argv_contains(const TokenHelperArgv* argv, const char* value)
{
	for (size_t x = 0; x < argv->count; x++)
	{
		if (strcmp(argv->items[x], value) == 0)
			return TRUE;
	}
	return FALSE;
}

/** The AVD resource scope plus the OpenID scopes the refresh token needs. */
static BOOL token_helper_avd_scopes(const rdpSettings* settings, TokenHelperArgv* out)
{
	static const char* extra[] = { "openid", "profile", "offline_access" };

	const char* scope = freerdp_settings_get_string(settings, FreeRDP_GatewayAvdScope);
	if (!token_helper_split_scope(scope, out))
		return FALSE;

	if (out->count == 0)
		return FALSE;

	for (size_t x = 0; x < ARRAYSIZE(extra); x++)
	{
		if (token_helper_argv_contains(out, extra[x]))
			continue;
		if (!token_helper_argv_add(out, extra[x]))
			return FALSE;
	}
	return TRUE;
}

/** Fill in the parts of @p request that come from @p settings. */
static void token_helper_request_from_settings(const rdpSettings* settings,
                                               TokenHelperRequest* request)
{
	WINPR_ASSERT(settings);
	WINPR_ASSERT(request);

	request->authority = freerdp_settings_get_string(settings, FreeRDP_GatewayAzureActiveDirectory);
	request->clientId = freerdp_settings_get_string(settings, FreeRDP_GatewayAvdClientID);

	request->tenant = "common";
	if (freerdp_settings_get_bool(settings, FreeRDP_GatewayAvdUseTenantid))
	{
		const char* tenant = freerdp_settings_get_string(settings, FreeRDP_GatewayAvdAadtenantid);
		if (tenant && (tenant[0] != '\0'))
			request->tenant = tenant;
	}
}

BOOL client_token_helper_should_fall_back(TokenHelperStatus status)
{
	return (status != TOKEN_HELPER_OK) && (status != TOKEN_HELPER_CANCELLED) &&
	       (status != TOKEN_HELPER_SERVER_ERROR);
}

BOOL client_token_helper_get_access_token(freerdp* instance, AccessTokenType tokenType,
                                          char** token, size_t count, ...)
{
	WINPR_ASSERT(instance);
	WINPR_ASSERT(instance->context);
	WINPR_ASSERT(token);

	const char* scope = nullptr;
	const char* req_cnf = nullptr;

	va_list ap = WINPR_C_ARRAY_INIT;
	va_start(ap, count);
	if ((tokenType == ACCESS_TOKEN_TYPE_AAD) && (count >= 2))
	{
		scope = va_arg(ap, const char*);
		req_cnf = va_arg(ap, const char*);
	}
	va_end(ap);

	*token = nullptr;

	const rdpSettings* settings = instance->context->settings;
	char* binary = client_token_helper_resolve(settings);
	TokenHelperStatus status = TOKEN_HELPER_NO_HELPER;

	if (binary)
	{
		TokenHelperArgv scopes = WINPR_C_ARRAY_INIT;
		TokenHelperRequest request = WINPR_C_ARRAY_INIT;

		token_helper_request_from_settings(settings, &request);

		BOOL prepared = FALSE;
		switch (tokenType)
		{
			case ACCESS_TOKEN_TYPE_AVD:
				prepared = token_helper_avd_scopes(settings, &scopes);
				break;
			case ACCESS_TOKEN_TYPE_AAD:
				prepared = token_helper_split_scope(scope, &scopes) && (scopes.count > 0);
				request.reqCnf = req_cnf;
				break;
			default:
				WLog_ERR(TAG, "unexpected AccessTokenType [%u]", tokenType);
				break;
		}

		if (prepared)
		{
			request.scopes = (const char* const*)scopes.items;
			request.scopeCount = scopes.count;
			status = client_token_helper_acquire(binary, &request, token);
		}

		token_helper_argv_free(&scopes);
		free(binary);
	}

	if (status == TOKEN_HELPER_OK)
	{
		WLog_INFO(TAG, "token helper supplied the %s token",
		          (tokenType == ACCESS_TOKEN_TYPE_AVD) ? "AVD" : "AAD");
		return TRUE;
	}

	if (!client_token_helper_should_fall_back(status))
	{
		WLog_ERR(TAG, "token helper failed: %s", client_token_helper_status_string(status));
		return FALSE;
	}

	if (status != TOKEN_HELPER_NO_HELPER)
		WLog_WARN(TAG, "token helper declined (%s), falling back to the browser flow",
		          client_token_helper_status_string(status));

	return client_cli_get_access_token(instance, tokenType, token, count, scope, req_cnf);
}
