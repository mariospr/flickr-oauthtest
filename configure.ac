AC_INIT([oauth-test], [0.1], [mario@mariospr.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])

#####################################
### Basic dependencies - Required ###
#####################################
PKG_CHECK_MODULES(REST, rest-0.7)
FOE_CFLAGS="$FOE_CFLAGS $REST_CFLAGS"
FOE_LIBS="$FOE_LIBS $REST_LIBS"

PKG_CHECK_MODULES(GLIB, glib-2.0)
FOE_CFLAGS="$FOE_CFLAGS $GLIB_CFLAGS"
FOE_LIBS="$FOE_LIBS $GLIB_LIBS"

PKG_CHECK_MODULES(LIBSOUP, libsoup-2.4)
FOE_CFLAGS="$FOE_CFLAGS $LIBSOUP_CFLAGS"
FOE_LIBS="$FOE_LIBS $LIBSOUP_LIBS"

# libgcrypt does not provide a .pc file
AM_PATH_LIBGCRYPT(,HAVE_GCRYPT=yes, HAVE_GCRYPT=no)
if test "x$HAVE_GCRYPT" = "xno"; then
   AC_MSG_ERROR([libgcrypt not found, please install it])
fi

AC_SUBST(FOE_CFLAGS)
AC_SUBST(FOE_LIBS)

############################
### Produce output files ###
############################

AC_CONFIG_FILES([
        Makefile
        src/Makefile
])
AC_OUTPUT

######################
### Status summary ###
######################
echo ""
echo "************************************************"
echo "*** flickr-oauthtest is ready to be compiled ***"
echo "************************************************"
echo ""
echo "Configure successful. Type 'make' to compile"
echo ""
