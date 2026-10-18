#!/usr/bin/env python3
import json
import sys
from client import ZeroKnowledgePIITokenVaultMasker

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        masker = ZeroKnowledgePIITokenVaultMasker()
        prompt = "Customer John Doe with email john.doe@example.com and SSN 123-45-6789 requested billing verification."
        res = masker.mask_prompt_pii(prompt)
        assert res["detected_pii_count"] == 2
        assert "john.doe@example.com" not in res["masked_prompt"]
        restored = masker.unmask_completion_pii(f"Verified {list(res['token_vault'].keys())[0]}", res["token_vault"])
        assert "@" in restored or "-" in restored
        print(f"[TEST PASS] ZK PII Masker Sanitized: {res['detected_pii_count']} PII tokens")
        sys.exit(0)

    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
            method = req.get("method")
            msg_id = req.get("id")
            if method == "initialize":
                print(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": {"serverInfo": {"name": "genpark-pii-masker", "version": "1.0.0"}}}))
            elif method == "tools/list":
                print(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": [
                    {"name": "mask_prompt_pii", "description": "Mask PII entities into synthetic tokens"},
                    {"name": "unmask_completion_pii", "description": "Restore real PII into completed text"}
                ]}}))
            elif method == "tools/call":
                args = req.get("params", {}).get("arguments", {})
                masker = ZeroKnowledgePIITokenVaultMasker()
                name = req.get("params", {}).get("name")
                if name == "unmask_completion_pii":
                    out = masker.unmask_completion_pii(args.get("masked_completion", ""), args.get("token_vault", {}))
                    print(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": {"content": [{"type": "text", "text": out}]}}))
                else:
                    out = masker.mask_prompt_pii(args.get("raw_prompt", ""), args.get("mask_salt", "default_secret_salt"))
                    print(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": {"content": [{"type": "text", "text": json.dumps(out)}]}}))
            else:
                print(json.dumps({"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Method not found"}}))
            sys.stdout.flush()
        except Exception as e:
            print(json.dumps({"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}}))
            sys.stdout.flush()

if __name__ == "__main__":
    main()
