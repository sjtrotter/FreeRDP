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

#ifndef FREERDP_CLIENT_COMMON_TOKEN_HELPER_H
#define FREERDP_CLIENT_COMMON_TOKEN_HELPER_H

#include <freerdp/api.h>
#include <freerdp/freerdp.h>

#ifdef __cplusplus
extern "C"
{
#endif

	/** @brief The outcome of one helper invocation.
	 *
	 *  The first eight values mirror the helper's documented exit codes; the remaining ones
	 *  describe failures on this side of the process boundary.
	 */
	typedef enum
	{
		TOKEN_HELPER_OK = 0,
		TOKEN_HELPER_INTERACTION_REQUIRED,
		TOKEN_HELPER_CANCELLED,
		TOKEN_HELPER_NO_ACCOUNT,
		TOKEN_HELPER_UNAVAILABLE,
		TOKEN_HELPER_SERVER_ERROR,
		TOKEN_HELPER_USAGE,
		TOKEN_HELPER_INTERNAL,
		TOKEN_HELPER_NO_HELPER,
		TOKEN_HELPER_SPAWN_FAILED,
		TOKEN_HELPER_TIMEOUT,
		TOKEN_HELPER_EMPTY,
		TOKEN_HELPER_UNKNOWN
	} TokenHelperStatus;

	/** @brief One @c token request, as the helper's command line spells it. */
	typedef struct
	{
		const char* authority;     /**< authority host, never a URL */
		const char* tenant;        /**< tenant identifier, or @c common */
		const char* clientId;      /**< public client id */
		const char* const* scopes; /**< decoded scopes */
		size_t scopeCount;
		const char* reqCnf; /**< base64url confirmation object; its presence requests PoP */
		const char* prompt; /**< auto, always, never; @c nullptr leaves the default */
		UINT32 timeoutMs;   /**< 0 selects @ref TOKEN_HELPER_DEFAULT_TIMEOUT_MS */
	} TokenHelperRequest;

/** The default bound on one helper run, generous enough for an interactive sign-in. */
#define TOKEN_HELPER_DEFAULT_TIMEOUT_MS 300000

	/** @return A stable, loggable name for @p status. */
	WINPR_ATTR_NODISCARD
	FREERDP_API const char* client_token_helper_status_string(TokenHelperStatus status);

	/** Resolve the helper binary to run.
	 *
	 *  @c FreeRDP_TokenHelperPath wins over @c FREERDP_TOKEN_HELPER, which wins over the
	 *  default name looked up on @c PATH. A path of @c off disables the helper.
	 *
	 *  @param settings Settings to consult, may be @c nullptr.
	 *  @return An allocated absolute path, or @c nullptr when disabled or not found.
	 */
	WINPR_ATTR_MALLOC(free, 1)
	WINPR_ATTR_NODISCARD
	FREERDP_API char* client_token_helper_resolve(const rdpSettings* settings);

	/** Run @p binary once and capture the access token it prints.
	 *
	 *  @param binary Helper executable.
	 *  @param request The request to make.
	 *  @param token Receives the trimmed token on @ref TOKEN_HELPER_OK.
	 *  @return The outcome; @p token is only written on @ref TOKEN_HELPER_OK.
	 */
	WINPR_ATTR_NODISCARD
	FREERDP_API TokenHelperStatus client_token_helper_acquire(const char* binary,
	                                                          const TokenHelperRequest* request,
	                                                          char** token);

	/** @return @c TRUE when @p status leaves FreeRDP free to try its own browser flow.
	 *
	 *  A cancelled transaction and an authorization server refusal are answers, not declines:
	 *  retrying interactively would ask the user or the server the same question again.
	 */
	WINPR_ATTR_NODISCARD
	FREERDP_API BOOL client_token_helper_should_fall_back(TokenHelperStatus status);

	/** A @c GetAccessToken implementation backed by the external helper.
	 *
	 *  Falls through to the callback set with @ref client_token_helper_set_fallback (or
	 *  @ref client_cli_get_access_token, its default) when the helper declines, and stops
	 *  when the user or the authorization server said no.
	 */
	FREERDP_API BOOL client_token_helper_get_access_token(freerdp* instance,
	                                                      AccessTokenType tokenType, char** token,
	                                                      size_t count, ...);

	/** Set the @c GetAccessToken callback used when the helper declines or is not configured.
	 *
	 *  A front-end that wants its own interactive flow (a web view, the terminal paste
	 *  prompt, ...) as the fallback calls this once, before installing
	 *  @ref client_token_helper_get_access_token as @c instance->GetAccessToken. Defaults to
	 *  @ref client_cli_get_access_token.
	 *
	 *  @param fallback The callback to defer to, or @c nullptr to restore the default.
	 */
	FREERDP_API void client_token_helper_set_fallback(pGetAccessToken fallback);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_CLIENT_COMMON_TOKEN_HELPER_H */
