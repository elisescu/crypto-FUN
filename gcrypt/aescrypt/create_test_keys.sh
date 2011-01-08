#!/bin/sh

dd if=/dev/urandom of=aes128.key bs=1 count=16
dd if=/dev/urandom of=aes192.key bs=1 count=24
dd if=/dev/urandom of=aes256.key bs=1 count=32
