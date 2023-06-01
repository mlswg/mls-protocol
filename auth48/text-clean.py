#!/usr/bin/env python

import sys
import re
import xml.etree.ElementTree as ET

file = sys.stdin.read()

# Tweak XML namespace expressions 
file = re.sub(r'xmlns:ns0=', 'xmlns=', file)
file = re.sub(r'<ns0:', '<', file)
file = re.sub(r'</ns0:', '</', file)

# Make sure there are spaces around <bcp14> tags
file = re.sub(r'><bcp14>', '> <bcp14>', file)
file = re.sub(r'></bcp14>', '> </bcp14>', file)

print(file)
