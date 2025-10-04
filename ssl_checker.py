import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse



def parse_cert_time(timestr):
    """parse to datetime object"""
    # Example format: 'Jun  1 12:00:00 2025 GMT'
    try:
        return datetime.strptime(timestr, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
    except Exception:
        return None
    

def ssl_checker(url): 
    """provides ssl information and detected risk flags"""

    result = {
        "ok": True,
        "tls_version": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_not_before": None,
        "cert_not_after": None,
        "valid_days": None,
        "self_signed": False,
        "risk_flags": [],
        "error": None
    }

    try:
        domain = urlparse(url).hostname
        # create context
        context = ssl.create_default_context()

        # create socket connection
        with socket.create_connection((domain,443)) as sock:
        # wrap the context
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
            # get ssl info
                version = ssock.version()
                result["tls_version"] = version

                cert = ssock.getpeercert()
        
                # issuer not being the free version?
                result["cert_issuer"] = cert.get('issuer')
                result["cert_subject"] = cert.get('subject')

                not_before = cert.get("notBefore")
                not_after  = cert.get("notAfter")
                nb_dt = parse_cert_time(not_before) if not_before else None
                na_dt = parse_cert_time(not_after) if not_after else None
                result["cert_not_before"] = not_before
                result["cert_not_after"]  = not_after

                if nb_dt and na_dt:
                    valid_days = (na_dt - nb_dt).days
                    result["valid_days"] = valid_days

                    # check expiry relative to now
                    now = datetime.now(timezone.utc)
                    if na_dt < now:
                        result["risk_flags"].append("certificate_expired")
                    elif (na_dt - now).days <= 20:
                        result["risk_flags"].append("certificate_expires_soon")

                # short validity might be a sign of free alternatives
                if result["valid_days"] is not None and result["valid_days"] <= 90:
                        result["risk_flags"].append("certificate_with_short_validity")

                # check for weak TLS versions 
                if result["tls_version"] is not None and result["tls_version"].lower().startswith("tlsv1.0"):
                        result["risk_flags"].append("tls_1_0_used")
                if result["tls_version"] is not None and result["tls_version"].lower().startswith("tlsv1.1"):
                        result["risk_flags"].append("tls_1_1_used")
    except Exception as e:
        result["ok"] = False
        result["error"] = f"Error fetching SSL/TLS info: {e}"

    return result

#print(ssl_checker("https://h2bet-jogos.com"))