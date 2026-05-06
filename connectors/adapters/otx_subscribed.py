from connectors.base import SafeConnector, ConnectorDecision


class OtxSubscribedConnector(SafeConnector):
    """Safe dry-run placeholder for OTX subscribed pulses/API source.

    This adapter intentionally does not read API keys or perform network calls.
    It only reports readiness metadata so the connector registry can represent
    otx_subscribed without enabling live collection.
    """

    source_id = "otx_subscribed"
    class_id = "open_api_requires_key"
    adapter_name = "OtxSubscribedConnector"
    requires_network = True
    requires_auth = True

    def dry_run(self) -> ConnectorDecision:
        decision = super().dry_run()
        decision.notes.append(
            "OTX source is represented as a placeholder only; no API key is read and no live request is made"
        )
        decision.expected_outputs.extend([
            "OTX readiness metadata only",
            "no pulse/content download in dry-run",
            "credential gate remains closed",
        ])
        return decision
