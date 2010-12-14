#!/bin/sh

PRF=libgt-0.3.8
LIBTOOLIZE_BIN="libtoolize"
if [ `(uname -s) 2>/dev/null` == 'Darwin' ]; then
  LIBTOOLIZE_BIN="glibtoolize"
fi

rm -f ${PRF}*.tar.gz && \
$LIBTOOLIZE_BIN && \
aclocal && \
automake -a && \
autoconf && \
./configure && \
make clean && \
make && \
make check && \
make doc && \
make dist && \
rm -rf ./${PRF} && \
make install prefix=$(pwd)/${PRF} && \
tar -czvf ${PRF}-bin.tar.gz ./${PRF} && \
rm -rf ./${PRF} && \
mkdir -p ./${PRF}/doc && \
cp -r ./doc/html ./doc/latex/refman.pdf ./${PRF}/doc && \
tar -czvf ${PRF}-doc.tar.gz ./${PRF}
