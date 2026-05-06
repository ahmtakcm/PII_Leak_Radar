from connectors.base import SafeConnector


class UrlHausRecentConnector(SafeConnector):
    source_id = "urlhaus_recent"
    class_id = "public_open_feed"
    adapter_name = "UrlHausRecentConnector"
    requires_network = True
    requires_auth = False
