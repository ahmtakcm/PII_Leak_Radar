from connectors.base import SafeConnector


class NvdRecentConnector(SafeConnector):
    source_id = "nvd_recent"
    class_id = "public_open_feed"
    adapter_name = "NvdRecentConnector"
    requires_network = True
    requires_auth = False
