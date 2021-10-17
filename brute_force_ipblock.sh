#!/bin/bash
sed '0~1 s/$/\npeter/g' rand > pass;
sed -e '/peter/! s/^.*$/carlos/g' pass > usr;
sed -i -e 's/peter/wiener/g' usr
