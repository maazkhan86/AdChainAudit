# Contributing to AdChainAudit 🛡️

Thanks for considering contributing — AdChainAudit is open to collaborators. 🚀  
If you care about **Supply Path Optimization (SPO)**, transparency, and buyer-relevant auditing, you’re in the right place.

This project aims to be:
- 🔎 **Evidence-first** (every finding should point to the exact line / artifact)
- 🎯 **Buyer-relevant** (signal what changes decision quality, not cosmetic noise)
- 🧱 **Composable** (small rule modules that scale from ads.txt → sellers.json → schain)

---

## 🧰 Local setup

### 1) Fork + clone
```bash
git clone https://github.com/<your-username>/AdChainAudit.git
cd AdChainAudit
```

### 2) Create a virtual environment
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
```

3) Install dependencies
```bash
pip install -r requirements.txt -r requirements-dev.txt
```

4) Run the app
```bash
streamlit run app.py
```

🧪 Tests
```bash
pytest -q
```

🧹 Lint
```bash
ruff check .
```

## 🛠️ Ways to contribute

- 🧪 **Add a new rule** (with test cases + examples)
- 🧱 **Improve scoring + severity logic**
- 🌐 **Implement `sellers.json` checks**
- 🕸️ **Build the supply-chain graph layer** (`schain`)
- 🧰 **Add CLI + GitHub Actions**
- 🧾 **Improve reporting** (JSON schema, PDF export, evidence trails)

---

## 🏁 Getting started

1. 🍴 **Fork the repo**
2. 🌿 **Create a feature branch** (`feature/your-thing`)
3. 🧫 **Add tests + sample fixtures** (if possible)
4. 📬 **Open a PR** with a clear description + screenshots (if UI)

---

## ✅ Rule PR checklist (simple)

When proposing a new check, please include:

- ⚠️ **What is the risk?**
- 🎯 **Why does a buyer care?**
- 🧠 **How does the tool detect it?**
- 🧾 **Example input → expected output**
- 🧪 **Tests included/updated** (strongly preferred)

## 🧭 Severity guide (recommended)

- 🟥 CRITICAL: malformed lines / invalid values / missing required fields

- 🟧 HIGH: relationship ambiguity, suspicious seller declarations, high buyer risk

- 🟨 MEDIUM: transparency gaps (e.g., missing optional IDs), cautionary signals

- 🟩 LOW: informational signals that don’t materially change buying decisions

## 🤝 Community

Be kind, be sharp, no ego.
If you want to collaborate on a big feature, open an issue titled:

Collab: <your idea> ✨
