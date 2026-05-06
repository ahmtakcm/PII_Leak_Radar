from connectors.base import SafeConnector


class CisaKevConnector(SafeConnector):
    source_id = "cisa_kev"
    class_id = "public_open_feed"
    adapter_name = "CisaKevConnector"
    requires_network = True
    requires_auth = False
