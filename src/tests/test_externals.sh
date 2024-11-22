#!/bin/sh

test -n "$JOHN" || JOHN=../../run/john

set -x

for mode in `$JOHN --list=ext-modes`; do
# KDEPaste's output depends on the current time
	if [ $mode != kdepaste ]; then
		$JOHN --external=$mode --stdout --max-candidates=10000
	fi
done

$JOHN --external=KDEPaste --stdout --max-candidates=10000 | sed 's/././g'

for mode in `$JOHN --list=ext-hybrids` `./john --list=ext-filters`; do
	$JOHN -w --external=$mode --stdout --max-candidates=10000
done
