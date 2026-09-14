#!/bin/bash
exec 3<>/dev/tcp/localhost/8080

printf 'GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' \
  "${KC_HTTP_RELATIVE_PATH}" >&3
timeout --preserve-status 5 cat <&3 \
  | grep -m 1 "HTTP/1.1" \
  | grep -m 1 "303 See Other"
status=$?

exec 3<&-
exec 3>&-

exit "$status"
