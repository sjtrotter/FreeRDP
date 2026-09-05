#!/bin/sh
# A stand-in for entra-token-helper. FAKE_TOKEN_HELPER_MODE selects the behaviour:
#
#   ok        print a token padded with whitespace and exit 0
#   empty     print nothing and exit 0
#   argv      print the argument vector on stdout and exit 0
#   hang      never exit
#   <number>  exit with that code, printing nothing on stdout
#
# FAKE_TOKEN_HELPER_TOKEN overrides the token printed in "ok" mode.

mode="${FAKE_TOKEN_HELPER_MODE:-ok}"
token="${FAKE_TOKEN_HELPER_TOKEN:-eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ0ZXN0In0.c2ln}"

case "${mode}" in
ok)
	printf '  \n%s\n\n' "${token}"
	exit 0
	;;
empty)
	printf '   \n'
	exit 0
	;;
argv)
	for arg in "$@"; do
		printf '%s\n' "${arg}"
	done
	exit 0
	;;
hang)
	exec sleep 3600
	;;
*)
	printf 'fake-token-helper: exiting %s\n' "${mode}" >&2
	exit "${mode}"
	;;
esac
