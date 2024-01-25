#! /bin/sh

# Copyright © inria 2009-2010
# Brice Goglin <Brice.Goglin@inria.fr>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

ORIGDIR=`pwd`
cd $srcdir

version=`sed -n /AC_INIT\(/,/\)/p configure.ac | tr -d '\n\t' | cut -d, -f2`
if test x$VERSION != x; then
	echo "Updating configure.ac version..."
	sed /AC_INIT\(/,/\)/s/"$version"/"$VERSION"/g -i configure.ac
	version="$VERSION"
fi
echo "Updating COPYING version..."
sed -e 's/^KNEM .*/KNEM '${version}'/' -i COPYING
echo "Updating knem.spec version..."
sed -e 's/^Version: .*/Version: '${version}'/' -i knem.spec
echo "Update dkms.conf version..."
sed -e 's/^PACKAGE_VERSION=.*/PACKAGE_VERSION=\"'${version}'\"/' -i dkms.conf

echo "Running autoreconf -ifv ..."
autoreconf -ivf

cd $ORIGDIR || exit $?
