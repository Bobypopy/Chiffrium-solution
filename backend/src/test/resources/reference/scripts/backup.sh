#!/bin/sh
openssl enc -des3 -salt -in dump.sql -out dump.sql.enc
openssl genrsa -out backup.key 2048
