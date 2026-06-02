from lxml import etree

def parse_config(xml_string: str) -> dict:
    """Parse XML configuration uploaded by user."""
    # VULNERABLE: external entity expansion enabled — can read /etc/passwd via XXE
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    root = etree.fromstring(xml_string.encode(), parser=parser)
    return {child.tag: child.text for child in root}
