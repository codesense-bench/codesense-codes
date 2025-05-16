"""
This script reformats all the build XMLs so that future modifications will result in clean diffs.
"""

from lxml import etree
from pathlib import Path

build_xmls = list(Path(".").glob("*_*/build.xml"))

count = 0
for xml in build_xmls:
    # Load the XML file
    tree = etree.parse(xml)
    # Save the modified XML tree back to the file
    tree.write(xml, encoding="utf-8", xml_declaration=True)
    count += 1

print(count, "files formatted")
