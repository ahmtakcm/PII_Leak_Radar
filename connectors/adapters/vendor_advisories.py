from connectors.base import SafeConnector


class VendorAdvisoriesConnector(SafeConnector):
    source_id = "vendor_advisories"
    class_id = "vendor_advisory"
    adapter_name = "VendorAdvisoriesConnector"
    requires_network = True
    requires_auth = False
