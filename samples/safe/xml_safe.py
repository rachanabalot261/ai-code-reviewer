from defusedxml import ElementTree

def parse_config(xml_string: str) -> dict:
    """Parse XML — XXE prevented via defusedxml library."""
    root = ElementTree.fromstring(xml_string)
    return {child.tag: child.text for child in root}
