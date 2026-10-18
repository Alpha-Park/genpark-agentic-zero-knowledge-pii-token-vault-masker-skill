from client import ZeroKnowledgePIITokenVaultMasker

def main():
    masker = ZeroKnowledgePIITokenVaultMasker()
    prompt = "Process refund for card 4111-2222-3333-4444 and email receipt to alice@company.org."
    res = masker.mask_prompt_pii(prompt)
    print("--- Zero-Knowledge PII Masking ---")
    print(f"Masked Prompt: {res['masked_prompt']}")
    print(f"Detected PII Count: {res['detected_pii_count']}")
    
    mock_llm_response = f"Refund confirmed for {list(res['token_vault'].keys())[0]}."
    unmasked = masker.unmask_completion_pii(mock_llm_response, res['token_vault'])
    print(f"Restored Completion: {unmasked}")

if __name__ == "__main__":
    main()
