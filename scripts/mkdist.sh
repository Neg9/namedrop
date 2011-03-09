#!/bin/sh -x

./scripts/_auto.sh

THIS_DIR=`basename $(pwd)`

if [ -f ../${THIS_DIR}.tar.gz ]
then
	mv ../${THIS_DIR}.tar.gz ../${THIS_DIR}.tar.gz.old
fi

(
	cd .. \
	&& \
	tar -cvf - ${THIS_DIR} | gzip -c9 > ${THIS_DIR}.tar.gz
)
