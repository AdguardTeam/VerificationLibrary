#!/bin/sh

curl https://hg.mozilla.org/releases/mozilla-release/raw-file/default/security/nss/lib/ckfw/builtins/certdata.txt -o certdata.txt -z certdata.txt
perl mk-ca-header.pl -n - < /dev/null  > CACertificates.h
perl mk-ca-header.pl -n -p SERVER_AUTH:NOT_TRUSTED - < /dev/null > CACertificatesUntrusted.h
rm certdata.txt
