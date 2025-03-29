from flask import request, current_app
from app.utils.crypto import get_public_key_jwk

def get_did_document():
    """生成DID文檔"""
    host = request.host
    protocol = current_app.config['ISSUER_PROTOCOL']
    base_url = f"{protocol}://{host}"
    
    # 構建標準的DID文檔
    did_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
            "https://identity.foundation/oid4vci/v1"
        ],
        "id": f"did:web:{host}",
        "verificationMethod": [{
            "id": f"did:web:{host}#key-1",
            "type": "JsonWebKey2020",
            "controller": f"did:web:{host}",
            "publicKeyJwk": get_public_key_jwk()
        }],
        "authentication": [f"did:web:{host}#key-1"],
        "assertionMethod": [f"did:web:{host}#key-1"],
        "service": [
            {
                "id": f"did:web:{host}#oid4vci",
                "type": "OID4VCIService",
                "serviceEndpoint": f"{base_url}/.well-known/openid-credential-issuer"
            },
            {
                "id": f"did:web:{host}#credential-status",
                "type": "CredentialStatusService",
                "serviceEndpoint": f"{base_url}/credential-status"
            },
            {
                "id": f"did:web:{host}#token-endpoint",
                "type": "OAuth2TokenService",
                "serviceEndpoint": f"{base_url}/token"
            },
            {
                "id": f"did:web:{host}#credential-endpoint",
                "type": "CredentialService",
                "serviceEndpoint": f"{base_url}/credential"
            },
            {
                "id": f"did:web:{host}#credential-offer",
                "type": "CredentialOfferService",
                "serviceEndpoint": f"{base_url}/credential-offer"
            }
        ]
    }
    
    return did_document