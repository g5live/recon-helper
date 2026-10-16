"""Learning guidance derived from observations; performs no network requests."""
from __future__ import annotations

from dataclasses import dataclass
from recon.scanner import PortFinding

@dataclass(frozen=True, slots=True)
class Explanation:
    meaning: str
    uncertainty: str
    next_check: str

def explain_finding(finding: PortFinding) -> Explanation:
    """Prefer observed protocol evidence to the service associated with a port."""
    if finding.detected_service == "SSH":
        return Explanation(
            "The endpoint advertised SSH, commonly used for remote administration.",
            "A banner does not establish patch status or prove a vulnerability.",
            "Confirm whether remote administration is expected on this host.",)
    if finding.web is not None:
        return Explanation(
            f"An HTTP response was recorded with status {finding.web.status}.",
            "The response may come from a redirect destination or intermediary; "
            "headers alone do not establish the underlying software or its security.",
            "Review the final URL and redirect count, then compare the page and "
            "headers with what you expect this service to provide.",)
    tls_guidance = explain_tls(finding)
    if tls_guidance is not None:
        return tls_guidance
    return Explanation(
        "The endpoint accepted a TCP connection on this port.",
        f"The port hint ({finding.service}) is a convention; the application "
        "protocol has not been confirmed by the supported checks.",
        "Compare the port with the host's expected services and confirm its "
        "protocol using an appropriate client in your authorised lab.",)

def explain_tls(finding: PortFinding) -> Explanation | None:
    """Explain the TLS result, if one is available."""
    if finding.tls is not None:
        if finding.tls.error:
            code = finding.tls.verification_code
            message = finding.tls.verification_message
            if code == 10:
                return Explanation(
                    "Certificate verification failed because the certificate "
                    "has expired.",
                    "This does not tell us whether the application itself "
                    "has other security problems.",
                    "Check the local clock, then check whether the service "
                    "needs a renewed certificate.",)
            if code == 9:
                return Explanation(
                    "Certificate verification failed because the certificate "
                    "is not valid yet.",
                    "The certificate's start date may be in the future, "
                    "or the local clock may be wrong.",
                    "Check the local clock and the certificate's start date.",)
            if code in (62, 64):
                return Explanation(
                    "The certificate does not match the hostname or IP "
                    "address used for this connection.",
                    "You may have used the wrong address, or the service "
                    "may be presenting the wrong certificate.",
                    "Check the intended hostname and whether the certificate "
                    "covers that hostname or IP address.",)
            if code in (18, 19):
                return Explanation(
                    "Certificate verification failed because a self-signed "
                    "certificate was found in the certificate chain.",
                    "This can be expected in a lab, but this client has "
                    "not established trust in the certificate.",
                    "Check who issued the certificate and whether your lab "
                    "has a trusted certificate authority to configure.",)
            if code in (20, 21):
                return Explanation(
                    "This client could not build a trusted certificate chain.",
                    "The service may be missing an intermediate certificate, "
                    "or this client may not trust the issuing authority.",
                    "Check the certificates supplied by the service and "
                    "the certificate authorities trusted by this client.",)
            if code is not None or message is not None:
                return Explanation(
                    "The certificate did not pass verification.",
                    "The recorded verification reason needs checking "
                    "before deciding what caused the failure.",
                    "Read the recorded TLS error and verification details, "
                    "then check the certificate and client configuration.",)
            return Explanation(
                "TLS inspection did not finish successfully.",
                "The recorded error may involve the connection, TLS "
                "negotiation or certificate verification.",
                "Read the TLS error first, then check the service address "
                "and configuration as appropriate.",)
        if finding.tls.certificate_verified:
            return Explanation(
                "TLS completed and the certificate passed this client's trust "
                "and target-identity checks.",
                "Certificate verification does not establish that the application is secure.",
                "Review the certificate names and validity dates against the intended service.",)
    return None