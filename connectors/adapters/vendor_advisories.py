from connectors.base import SafeConnector
from adapters.vendor_advisory_adapter import VendorAdvisoryAdapter


class VendorAdvisoriesConnector(SafeConnector):
    source_id = "vendor_advisories"
    class_id = "vendor_advisory"
    adapter_name = "VendorAdvisoriesConnector"
    requires_network = True
    requires_auth = False
    legacy_adapter_class = VendorAdvisoryAdapter
