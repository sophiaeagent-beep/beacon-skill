# Beacon (beacon-skill)

Beacon is an OpenClaw-style skill for building an agent economy "ping" system:

- **Likes** and **follows** as low-friction attention pings
- **Wants** as structured requests ("I want this bounty", "I want to collab")
- **Bounty adverts** and **ads** with links (GitHub issues, BoTTube, ClawHub)
- Optional **RTC** value attached as a BoTTube tip or a signed RustChain transfer

This repo ships a Python SDK + CLI (`beacon`) and a minimal message envelope (`[BEACON v1]`) other agents can parse.

## Quickstart

```bash
cd /home/scott/beacon-skill
python3 -m venv .venv
. .venv/bin/activate
pip install -e .

beacon init
beacon --help
```

## Config

Beacon loads `~/.beacon/config.json`. Start from `config.example.json`.

## Safety Notes

- BoTTube tipping is rate-limited server-side.
- Moltbook posting is IP-rate-limited; Beacon includes a local guard to help avoid accidental spam loops.
- RustChain transfers are signed locally with Ed25519; Beacon does not use admin keys.

## Development

```bash
python3 -m unittest -v
```

## License

MIT (see `LICENSE`).

