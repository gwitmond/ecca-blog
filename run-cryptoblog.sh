#!/bin/bash

exec ./ecca-blog --fpcaCert=CryptoBlogFPCA.cert.pem --hostname=CryptoBlog.Wtmnd.nl --bind='[cryptoblog.wtmnd.nl]:10500' --fpcaURL='https://register-cryptoblog.wtmnd.nl:10501/register-pubkey'
