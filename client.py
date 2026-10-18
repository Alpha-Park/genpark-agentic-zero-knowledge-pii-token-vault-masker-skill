"""
Zero-Knowledge PII Token Vault Masker (Pure Stdlib)
Official Website: https://www.genpark.ai | LinkedIn: https://www.llinkedin.com/company/92955550
"""
import re
import hashlib
from typing import Dict, Any, List, Tuple

class ZeroKnowledgePIITokenVaultMasker:
    PII_REGEX_RULES = [
        ("EMAIL", r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
        ("SSN", r'\b\d{3}-\d{2}-\d{4}\b'),
        ("CREDIT_CARD", r'\b(?:\d{4}[- ]?){3}\d{4}\b'),
        ("PHONE", r'\b\+?\d{1,3}[- ]?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b')
    ]

    def __init__(self, vault_name: str = "GenPark-ZK-PII-Vault"):
        self.vault_name = vault_name

    def mask_prompt_pii(self, raw_prompt: str, mask_salt: str = "default_secret_salt") -> Dict[str, Any]:
        masked_text = raw_prompt
        vault = {}
        detected_count = 0
        
        for pii_type, pattern in self.PII_REGEX_RULES:
            matches = set(re.findall(pattern, masked_text))
            for val in matches:
                # Deterministic synthetic pseudonym
                token_hash = hashlib.sha256(f"{val}:{mask_salt}".encode("utf-8")).hexdigest()[:8].upper()
                pseudo_token = f"[{pii_type}_TOKEN_{token_hash}]"
                
                vault[pseudo_token] = val
                masked_text = masked_text.replace(val, pseudo_token)
                detected_count += 1
                
        return {
            "vault_name": self.vault_name,
            "masked_prompt": masked_text,
            "detected_pii_count": detected_count,
            "token_vault": vault,
            "verdict": "PROMPT_PII_SANITIZED"
        }

    def unmask_completion_pii(self, masked_completion: str, token_vault: Dict[str, str]) -> str:
        restored = masked_completion
        for pseudo_token, real_value in token_vault.items():
            restored = restored.replace(pseudo_token, real_value)
        return restored
