# Model Pack & Lock Files

This directory contains model configuration and integrity verification files.

## Files

### MODEL_PACK.json
Comprehensive model pack configuration containing:
- **ASR Pack**: Primary and shadow models with tier definitions
  - baseline_conformer (800ms, CPU)
  - enhanced_transducer (650ms, GPU)
  - realtime_streaming (250ms, GPU)
- **LLM Tiers**: Lite, Standard, Premium with token budgets
- **TTS Pack**: Primary (VITS multilingual) and fallback (Tacotron2)
- **Latency Profile**: Per-service targets and P99 thresholds
- **Residency Policy**: Multi-region deployment rules
- **Lexicon**: Custom pronunciations, domain-specific terms
- **Token Budget**: Global and per-user rate limits

### MODEL_LOCK.json
Integrity manifest with ECDSA signatures:
- **Manifest**: SHA256 checksums for all model files
- **ECDSA Signatures**: secp256k1 signatures for each artifact
- **Verification Policy**: Safe-mode rules and failure actions
- **Compliance**: TRD v2.2, ISO 27001, SOC 2 Type II
- **Runtime State**: Current system mode and verification status

## Usage

### Verify Model Integrity
```bash
# Run full verification
python ../services/asr/verify_model_lock.py

# Output: Exit 0 if all verified, Exit 1 if mismatch
```

### Generate Signatures
```bash
# Sign all models (requires private key)
python generate_signatures.py

# Generates/loads ECDSA key pair
# Signs all models in manifest
# Updates MODEL_LOCK.json
```

### Safe Mode Behavior
If verification fails:
1. System enters **safe mode** automatically
2. Restrictions applied:
   - Disable external requests
   - Use fallback models only
   - Log all operations
   - Alert security team
3. Only allowed operations:
   - Health checks
   - Metrics export
   - Audit logging

## TRD v2.2 Compliance

✅ **Model Integrity**: SHA256 checksums for all artifacts
✅ **Digital Signatures**: ECDSA (secp256k1) signatures
✅ **Safe Mode**: Automatic activation on mismatch
✅ **Audit Trail**: 365-day retention
✅ **SBOM**: Software Bill of Materials generated
✅ **Vulnerability Scanning**: Trivy integration

## File Structure

```
ops/
├── MODEL_PACK.json          # Model configuration
├── MODEL_LOCK.json          # Integrity manifest
├── generate_signatures.py   # Signature generation tool
├── latency_profile.json     # Legacy latency config
├── alerts.yaml             # Prometheus alerts
└── certs/                  # Signing certificates
    ├── model-signing-key.pem       # Private key (keep secure!)
    ├── model-signing-cert.pem      # Public certificate
    └── smartlite-*.pem             # CA chain
```

## Security Notes

⚠️ **CRITICAL**: Never commit `model-signing-key.pem` to version control

✅ Store private key in secure vault (HashiCorp Vault, AWS KMS)
✅ Rotate signing keys every 90 days
✅ Use hardware security module (HSM) in production
✅ Audit all signature operations

## Verification Policy

The verification policy in MODEL_LOCK.json defines:
- `enforce_signatures`: Require valid ECDSA signatures
- `require_all_verified`: All models must pass checksum
- `safe_mode_on_mismatch`: Auto-activate safe mode
- `allow_shadow_fallback`: Use shadow models if primary fails

## Failure Actions

| Failure Type | Action |
|-------------|--------|
| Checksum mismatch | Enter safe mode |
| Invalid signature | Halt system |
| Missing model | Use shadow model |
| Expired verification | Re-validate immediately |

## Support

For issues with model verification:
1. Check audit logs: `logs/audit/model_verification.log`
2. Review runtime state in MODEL_LOCK.json
3. Contact security-ops@smartlite.example.com
