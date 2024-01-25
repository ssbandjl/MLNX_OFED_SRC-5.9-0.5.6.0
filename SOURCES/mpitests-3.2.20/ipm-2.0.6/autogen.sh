#!/bin/sh
#set -ex

# clean up earlier configuration
if [ -f Makefile ]; then
	make distclean
fi

rm -rf autom4te.cache

mkdir -p config/m4 config/aux 

autoreconf -v --install || exit 1
rm -rf autom4te.cache
 
# apply the fix
mv m4/libtool.m4 m4/libtool.m4_orig
awk '{ print $0 } /-L\* \| -R\* \| -l\*\)/ { printf("\n\t# Some compilers *also* place space between \"-l\" and the library name.\n\t# Remove the space.\n\tif test $p = \"-l\"; then prev=$p; continue; fi\n\n"); }' m4/libtool.m4_orig > m4/libtool.m4

# Fix for ARM build 
if [ "$CXX" = "armclang++" ]; then
    sed -i '/^_LT_TAGVAR(lt_prog_compiler_wl/ s/$/"-Wl,"/' m4/libtool.m4
fi

exit 0
