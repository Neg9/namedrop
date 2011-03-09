#!/bin/sh -xe

host=kame220
domain=kame.net

./namedrop -ve6r ${host}.${domain}/117
./namedrop -ve6r 2001:200:0:8002:203:47ff:fea5:3085/117
./namedrop -ve6rS 2001:200:0:8002:203:47ff:fea5:3085/117
./namedrop -ve6rs ${host}.${domain}/117
./namedrop -ve6Sr ${host}.${domain}/117
./namedrop -ver4 ${host}.${domain}/25
./namedrop -ver4 203.178.141.194/25
./namedrop -ver4S 203.178.141.194/25
./namedrop -ver4s ${host}.${domain}/25
./namedrop -verS4 ${host}.${domain}/25
./namedrop -ve4 ${domain}
./namedrop -ve6 ${domain}
./namedrop -ve ${domain}
./namedrop -ves ${domain}
./namedrop -veS ${domain}
./namedrop -vef oz ${domain}
./namedrop -veb 1-2 ${domain}
./namedrop -veb 3-3 -c cvswftpo ${domain}
