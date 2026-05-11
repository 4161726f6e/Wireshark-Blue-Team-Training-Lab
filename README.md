# Wireshark-Blue-Team-Training-Lab
Seeded lab generator producing synthetic SOC training artifacts (PCAP-only Wireshark investigation)

# PCAP-Only Blue Team Lab Generator

This repository provides a generator for synthetic blue-team training labs, focusing on **evidence-based analysis**.

Primary tool: **PCAP-only Wireshark investigation lab generator** (seeded variants, unambiguous answers, built-in validation).

Optional tool: Cloud/SaaS hybrid lab generator (PCAP + logs + config export).

## Why PCAP-Only?
PCAP is the ground truth of network activity, enabling analysts to validate protocols, session behavior, timing patterns, and payload characteristics. This lab style intentionally includes heavy enterprise-like noise so attackers represent a small fraction of total traffic. (This mirrors real SOC conditions.)  

## What This Generates (PCAP-only lab)
Each run produces:
- `enterprise_attack.pcap` — enterprise noise + 1 successful attack chain + 3 failed chains
- `ctfd_challenges.txt` — 10 Wireshark-focused questions (increasing difficulty)
- `ctfd_hints.txt` — tiered hints (3 levels per question)
- `instructor_answers.txt` — answers + point values
- `validation_report.txt` — proof that each answer exists in the PCAP and is uniquely derivable
- `metadata.json` — seed + scenario ground truth for reproducibility

## Key Design Features
- **Seeded variation**: same workflows, different answers per run
- **Stealth mode**: adds realistic decoys (e.g., near-miss bulk transfers) while keeping answers unambiguous
- **Duration control**: spreads traffic across a realistic timeline window
- **Validation-first**: generator re-reads the PCAP and confirms each answer can be derived via the intended pivots

---

# Installation

## Dependencies
- Python 3.9+
- scapy

Install:
```bash
pip install -r requirements.txt

## Example Usage
- Run with a seed (required):
```bash
python tools/generate_pcap_only_lab.py --seed 1337 --output lab_1337
- High-noise + long capture window:
```bash
python tools/generate_pcap_only_lab.py --seed 1337 --noise high --duration 3600 --output lab_1337
- High-noise + stealth decoys:
```bash
High-noise + stealth decoys:
