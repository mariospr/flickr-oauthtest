#!/bin/sh

set -e
aclocal
autoconf --force
autoheader --force
automake --add-missing --copy --force-missing --foreign

./configure $@
