# Guardian Simulation Suite

This folder contains attack-surface scenarios that mirror the Guardian implementation guide and the current analyzer stack.

## Covered scenarios

- `address_poisoning`
- `dust_attack`
- `approval_attack`
- `behavioral_anomaly`
- `ica_abuse`
- `simulated_contract_abuse`

## Purpose

The suite serves three roles:

1. Regression coverage for the current risk detectors
2. Demo fixtures for the hackathon walkthrough
3. A foundation for later profile-driven, end-to-end simulations that notify the registered user destination

## Run

```bash
cargo test -p guardian-simulations
```
