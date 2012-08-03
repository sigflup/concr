export AUTOCONF_VERSION=2.59
export AUTOMAKE_VERSION=1.4

make -i clean
make -i distclean
aclocal && autoconf
