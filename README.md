# 🛡️ AdChainAudit

**Audit the ad supply chain — starting with `ads.txt`** 🔍

AdChainAudit is a **serious, hacker-style** toolkit for **Supply Path Optimization (SPO)** and supply-chain transparency.  
Today: It audits `ads.txt` for buyer-relevant red flags (with line-level evidence).  
Next: It evolves into a full **ad supply-chain auditor** (e.g., `sellers.json`, `schain`, hop graphs, SPO scoring, monitoring, and reports).

---

## 🚨 Why this matters? (Industry reality)

Programmatic supply chains are **complex**, **costly**, and still **hard to verify end-to-end**.

- **ads.txt exists to reduce counterfeit inventory and increase transparency.** It creates a public record of authorized sellers so buyers can more easily identify legitimate supply.  
  Source: IAB Tech Lab (ads.txt) — https://iabtechlab.com/ads-txt/ and https://iabtechlab.com/ads-txt-about/

- **Supply-chain leakage is measurable.** The ISBA/PwC study found that, on average, **~51%** of advertiser spend reached publishers (“working media”), and **~15%** was an “unknown delta” that couldn’t be attributed.  
  Source: ISBA/PwC Executive Summary PDF — https://www.isba.org.uk/system/files/media/documents/2020-12/executive-summary-programmatic-supply-chain-transparency-study.pdf

- **Fraud waste is massive.** Juniper Research (via PRNewswire) estimated **22% ($84B)** of online ad spend lost to ad fraud in **2023**, projected to exceed **$170B** in 5 years.  
  Source: PRNewswire — https://www.prnewswire.com/news-releases/new-ad-fraud-study-22-of-online-ad-spend-is-wasted-due-to-ad-fraud-in-2023-according-to-juniper-research-301938050.html

- **Even efficiency improvements still leave a lot on the table.** The ANA’s 2024 Programmatic Benchmark reporting highlights that for every **$1,000 entering a DSP, 43.9% reaches consumers** (as reported publicly).  
  Sources: ANA press release — https://www.ana.net/content/show/id/pr-2024-12-programmatic  
  and industry coverage — https://www.marketingdive.com/news/programmatic-efficient-transparent-ctv-marketing-ana/735645/

**Bottom line:** SPO isn’t just about cheaper CPMs — it’s about **provable paths**. AdChainAudit is built to make those paths auditable. ✅

---

## ✅ What AdChainAudit does today (MVP)

Upload (or paste) an `ads.txt` file and get:

- 📊 A simple **risk score**
- 🧾 A **buyer-friendly summary** of potential red flags
- 🧷 **Line-level evidence** (what, where, why it matters)
- ⬇️ Exportable **JSON report**

### Red flags (initial rule set)
- ❌ Malformed lines (wrong number of fields)
- ❌ Invalid relationship values (must be `DIRECT` or `RESELLER`)
- ⚠️ Missing Certification Authority ID (transparency/verification gap)
- ⚠️ Relationship ambiguity (same seller listed as `DIRECT` and `RESELLER`)

> Philosophy: **evidence-first**, **buyer-relevant**, not “cosmetic lint”.

---

🧠 Roadmap (where this is going)
Phase 1 — Ads.txt hardening (now)

✅ Ads.txt parsing + validation

✅ Risk scoring + red-flag report

⬜ Domain mode: example.com → fetch https://example.com/ads.txt

⬜ Change detection: diff + alerts (new sellers, new resellers, new risk)

Phase 2 — Seller verification (sellers.json)

⬜ Fetch/validate sellers.json per ad system (SSP/exchange)

⬜ Verify seller IDs + seller type + declared domains (when available)

⬜ Evidence locker (store fetched artifacts + timestamps)

Phase 3 — Full supply-chain graph

⬜ Parse and map schain (SupplyChain object) into a hop graph

⬜ SPO scoring: hops, reseller concentration, unknown hops, path cleanliness

⬜ Buyer controls: allowlists / blocklists / preferred paths

Phase 4 — Operator mode (serious tooling)

⬜ CLI: adchainaudit scan <domain|file>

⬜ GitHub Action / CI checks for publisher ops & adops workflows

⬜ Dashboards + scheduled scans + PDF buyer packs

## 🤝 Contributing (yes please!)

I’m **very open** to collaborators — engineers, adops folks, SPO nerds, agency buyers, SSP/DSP people.  
If this problem space excites you, jump in. 🚀

### 🛠️ Ways to contribute
- 🧪 **Add a new rule** (with test cases + examples)
- 🧱 **Improve scoring + severity logic**
- 🌐 **Implement `sellers.json` checks**
- 🕸️ **Build the supply-chain graph layer** (`schain`)
- 🧰 **Add CLI + GitHub Actions**
- 🧾 **Improve reporting** (JSON schema, PDF export, evidence trails)

### 🏁 Getting started
1. 🍴 **Fork the repo**
2. 🌿 **Create a feature branch** (`feature/your-thing`)
3. 🧫 **Add tests + sample fixtures** (if possible)
4. 📬 **Open a PR** with a clear description + screenshots (if UI)

### ✅ Rule PR checklist (simple)
- ⚠️ **What is the risk?**
- 🎯 **Why does a buyer care?**
- 🧠 **How does the tool detect it?**
- 🧾 **Example input → expected output**

💬 Community & Collaboration

Use Issues for bugs, feature requests, and rule proposals

Use Discussions for SPO ideas, scoring debates, and roadmap planning

Be kind. Be sharp. No ego. 🫶

If you want to collaborate closely, open an issue titled:
“Collab: <what you want to build>” — I’ll respond and we’ll align.

🔒 Security / Responsible Disclosure

If you discover a vulnerability (especially around file uploads or fetching remote URLs), please open a private disclosure path if available, or file a minimal issue without exploit details.

📄 License

Recommended: MIT (simple, friendly for open-source tooling).
Add a LICENSE file when you’re ready.

📚 References

IAB Tech Lab — ads.txt
https://iabtechlab.com/ads-txt/

https://iabtechlab.com/ads-txt-about/

ISBA/PwC — Programmatic Supply Chain Transparency Study (Exec Summary PDF)
https://www.isba.org.uk/system/files/media/documents/2020-12/executive-summary-programmatic-supply-chain-transparency-study.pdf

Juniper Research (via PRNewswire) — 2023 ad fraud estimate
https://www.prnewswire.com/news-releases/new-ad-fraud-study-22-of-online-ad-spend-is-wasted-due-to-ad-fraud-in-2023-according-to-juniper-research-301938050.html

ANA — 2024 Programmatic Benchmark Study (press release + reporting)
https://www.ana.net/content/show/id/pr-2024-12-programmatic

https://www.marketingdive.com/news/programmatic-efficient-transparent-ctv-marketing-ana/735645/

## 🏁 Quickstart (local)

### 1) Setup
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

