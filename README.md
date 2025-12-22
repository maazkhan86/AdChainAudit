# 🛡️ AdChainAudit

**Audit the programmatic ad supply chain, starting with `ads.txt`** 🔍  
A serious, hacker-style toolkit for **Supply Path Optimization (SPO)** and supply-chain transparency.

✅ Built for **marketers, agencies, adops, publisher ops, and procurement**  
👩‍💻 Open source for **technical contributors** (GitHub)

**Live app:** https://adchainaudit.streamlit.app/  
**Repo:** https://github.com/maazkhan86/AdChainAudit

---

## 🚨 Why this matters (industry reality)

Programmatic supply chains are complex, costly, and still hard to verify end-to-end.

- **ads.txt exists to reduce counterfeit inventory and increase transparency.** It is a public record of authorized sellers.  
  Source: IAB Tech Lab (ads.txt)  
  https://iabtechlab.com/ads-txt/  
  https://iabtechlab.com/ads-txt-about/

- **Supply-chain leakage is measurable.** ISBA/PwC found ~51% of spend reached publishers (“working media”), with ~15% as an “unknown delta” in the studied supply chain.  
  Source: ISBA/PwC Exec Summary PDF  
  https://www.isba.org.uk/system/files/media/documents/2020-12/executive-summary-programmatic-supply-chain-transparency-study.pdf

- **Fraud waste is massive.** Juniper Research (via PRNewswire) estimated 22% ($84B) of online ad spend was wasted due to ad fraud in 2023, projected to exceed $170B in 5 years.  
  Source: PRNewswire  
  https://www.prnewswire.com/news-releases/new-ad-fraud-study-22-of-online-ad-spend-is-wasted-due-to-ad-fraud-in-2023-according-to-juniper-research-301938050.html

- **Even “efficiency improvements” still leave a lot on the table.** ANA’s 2024 Programmatic Benchmark reporting highlights that for every $1,000 entering a DSP, 43.9% reaches consumers (as reported publicly).  
  Sources: ANA press release + industry coverage  
  https://www.ana.net/content/show/id/pr-2024-12-programmatic  
  https://www.marketingdive.com/news/programmatic-efficient-transparent-ctv-marketing-ana/735645/

**Bottom line:** SPO is not just about cheaper CPMs. It is about **provable paths**. ✅

---

## ✅ What AdChainAudit does (today)

### Phase 1: ads.txt audit (live)
Upload (or paste) an `ads.txt` file and get:

- 📊 A simple **risk score**
- 🧾 A **buyer-friendly summary** of potential red flags
- 🧷 **Line-level evidence** (what, where, why it matters)
- ⬇️ Exportable reports (**JSON / TXT / CSV**)

**Initial red-flag rules**
- ❌ Malformed lines (wrong number of fields)
- ❌ Invalid relationship values (must be `DIRECT` or `RESELLER`)
- ⚠️ Missing Certification Authority ID (optional signal)
- ⚠️ Relationship ambiguity (same seller listed as `DIRECT` and `RESELLER`)

> Philosophy: evidence-first, buyer-relevant, not “cosmetic lint”.

### Phase 2: sellers.json verification (live)
When enabled, AdChainAudit can **verify ad systems from ads.txt** against **sellers.json** signals, to help answer questions like:
- “Is this seller ID declared in sellers.json?”
- “Does sellers.json classify them as PUBLISHER or INTERMEDIARY?”
- “Are there obvious mismatches that deserve follow-up?”

⚠️ Note: Some endpoints may block automated fetches. If a fetch fails, the app should guide you to upload inputs manually where possible.

---

## 🧾 How to get an ads.txt (for any site)

1) Open: `https://example.com/ads.txt`  
2) If it 404s, try: `https://www.example.com/ads.txt`  
3) Copy all text and paste it into AdChainAudit, or save it as `ads.txt` and upload.

### Demo input (built-in)
The app includes a sample snapshot so you can test instantly:  
`thestar.com.my/ads.txt` (captured 14 Dec 2025)

ads.txt changes over time. Treat this as demo input only.

---

## 🧠 Roadmap (where this is going)

### Phase 1 — Ads.txt hardening
✅ Ads.txt parsing + validation  
✅ Risk scoring + red-flag report  
⬜ Domain mode: `example.com` → fetch `https://example.com/ads.txt`  
⬜ Change detection: diff + alerts (new sellers, new resellers, new risk)

### Phase 2 — Seller verification (sellers.json)
✅ Fetch/validate sellers.json per ad system (when accessible)  
✅ Verify seller IDs + seller type + declared domains (when available)  
⬜ Evidence locker (store fetched artifacts + timestamps)

### Phase 3 — Full supply-chain graph
⬜ Parse and map `schain` into a hop graph  
⬜ SPO scoring: hops, reseller concentration, unknown hops, path cleanliness  
⬜ Buyer controls: allowlists / blocklists / preferred paths

### Phase 4 — Operator mode
⬜ CLI: `adchainaudit scan <domain|file>`  
⬜ GitHub Actions / CI checks for publisher ops workflows  
⬜ Dashboards + scheduled scans + PDF buyer packs

---

## 🤝 Contributing (yes please!)

I’m very open to collaborators, including engineers, adops folks, SPO nerds, agency buyers, SSP/DSP people. If this problem space excites you, jump in. 🚀

### 🛠️ Ways to contribute
- 🧪 Add a new rule (with test cases + examples)
- 🧱 Improve scoring + severity logic
- 🌐 Improve sellers.json checks (coverage, resilience, mappings)
- 🕸️ Build the supply-chain graph layer (schain)
- 🧰 Add CLI + GitHub Actions
- 🧾 Improve reporting (JSON schema, PDF export, evidence trails)

### 🏁 Getting started
1. 🍴 Fork the repo  
2. 🌿 Create a feature branch (`feature/your-thing`)  
3. 🧫 Add tests + sample fixtures (if possible)  
4. 📬 Open a PR with a clear description + screenshots (if UI)

### ✅ Rule PR checklist (simple)
- ⚠️ What is the risk?
- 🎯 Why does a buyer care?
- 🧠 How does the tool detect it?
- 🧾 Example input → expected output

### 💬 Community
- Use **Issues** for bugs, feature requests, and rule proposals
- Use **Discussions** for SPO ideas, scoring debates, and roadmap planning
- Be kind. Be sharp. No ego. 🫶

If you want to collaborate closely, open an issue titled:  
**“Collab: <what you want to build>”** and I’ll respond.

---

## 🔒 Security / Responsible Disclosure

If you discover a vulnerability (especially around file uploads or fetching remote URLs), please avoid posting exploit details publicly. Share a minimal report via a safe channel if available, or file a minimal issue without sensitive payloads.

---

## 📄 License

**MIT License.** See `LICENSE`.

---

## 🏁 Quickstart (local)

### 1) Setup
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
