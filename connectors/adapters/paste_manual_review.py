from connectors.base import SafeConnector


class PasteManualReviewConnector(SafeConnector):
    source_id = "paste_leak_manual_review"
    class_id = "paste_manual_review"
    adapter_name = "PasteManualReviewConnector"
    requires_network = False
    requires_auth = False
    supports_local_files = True
    supports_manual_review = True
