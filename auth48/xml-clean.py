#!/usr/bin/env python

import sys
import re
import xml.etree.ElementTree as ET

file = sys.stdin.read()
root = ET.fromstring(file)

# Strip "removeInRFC" notes
for parent in root.findall(".//note[@removeInRFC='true']/.."):
    for child in parent.findall("./note[@removeInRFC='true']"):
        parent.remove(child)
        parent.tail = None

# Remove <t> internal to <dd>
for dd in root.findall(".//dd/t/.."):
    t = dd.find("./t")
    dd.remove(t)

    dd.text = t.text
    for sub in t:
        t.remove(sub)
        dd.append(sub)
    dd.tail = t.tail

# Convert all-whitespace text/tail to None
for node in root.findall(".//*"):
    if node.text and re.match(r'^\s+$', node.text):
        node.text = None
    if node.tail and re.match(r'^\s+$', node.tail):
        node.tail = None

# Remove trailing whitespace from SVG polygons 
for node in root.findall(".//{http://www.w3.org/2000/svg}polygon"):
    if node.attrib['points']:
        node.attrib['points'] = re.sub(r'\s*$', '', node.attrib['points'])

xml = ET.tostring(root, encoding='unicode', method='xml')
print(xml)
