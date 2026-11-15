#!/bin/sh
# second angle: the project's own tool (tpm2_checkquote 5.4 in their image) on our copies
cd /x || exit 2
QA=$(sed -n 's/^qualifying data A *= \([0-9a-f]*\).*/\1/p' /r/run.log)
tpm2_checkquote -u ak.pub -m runA.msg -s runA.sig -f runA.pcrs -q "$QA" -g sha256 >/dev/null 2>&1; echo "clean quote, right qualifying data: exit=$?"
tpm2_checkquote -u ak.pub -m runA-flip.msg -s runA.sig -f runA.pcrs -q "$QA" -g sha256 >/dev/null 2>&1; echo "one byte of TPMS_ATTEST flipped: exit=$?"
tpm2_checkquote -u ak.pub -m runA.msg -s runA.sig -f runA.pcrs -q 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff -g sha256 >/dev/null 2>&1; echo "clean quote, other qualifying data: exit=$?"
