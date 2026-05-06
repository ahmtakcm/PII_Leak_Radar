from connectors.base import SafeConnector


class ManualImportConnector(SafeConnector):
    source_id = "manual_import"
    class_id = "manual_import"
    adapter_name = "ManualImportConnector"
    requires_network = False
    requires_auth = False
    supports_local_files = True
