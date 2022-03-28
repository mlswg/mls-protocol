#!/usr/bin/env python3
import sys
import re

match = False

for line in sys.stdin:
	if match:
		if re.match('^~~~$', line):
			match = False
			print ('')
		else:
			print (line.rstrip())
	elif re.match('^~~~ tls$', line):
		match = True
