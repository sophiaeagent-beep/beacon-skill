# Beacon Publishing Checklist

## 1. GitHub

```bash
cd /home/scott/beacon-skill
git init
git add -A
git commit -m "beacon-skill v0.1.0"

# Create repo on GitHub (example)
# gh repo create Scottcjn/beacon-skill --public --source=. --remote=origin --push
```

## 2. ClawHub Registration

ClawHub API base: `https://clawhub.ai/api/v1`

```bash
curl -X POST https://clawhub.ai/api/v1/skills \\
  -H "Authorization: Bearer YOUR_CLAWHUB_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "beacon",
    "description": "Agent-to-agent pings with optional RTC value attached (BoTTube, Moltbook, RustChain)",
    "version": "0.1.0",
    "tags": ["pings", "agent-economy", "bounties", "ads", "rustchain", "bottube", "moltbook"],
    "platforms": ["bottube", "moltbook", "rustchain"],
    "pypi_package": "beacon-skill",
    "github_repo": "Scottcjn/beacon-skill"
  }'
```

## 3. PyPI (Optional)

Use a venv or `pipx`.

```bash
cd /home/scott/beacon-skill
python3 -m venv .venv
. .venv/bin/activate
pip install -U build twine
python -m build
twine upload dist/*
```

