# app.py

import io
import os
import sys
import glob
import time
import pathlib
import subprocess
from datetime import datetime

import pandas as pd
import streamlit as st

# --- Paths ---
BASE_DIR = pathlib.Path(os.getcwd()).resolve()
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "outputs"
SCRIPTS_DIR = BASE_DIR / "scripts"
STATIC_DIR = BASE_DIR / "static"

for d in (DATA_DIR, OUTPUT_DIR, SCRIPTS_DIR):
    d.mkdir(parents=True, exist_ok=True)

# --- Page config ---
st.set_page_config(
    page_title="Venator Cyber Threat Intelligence",
    page_icon=STATIC_DIR / "logo.png",
    layout="wide"
)

col1, col2 = st.columns([1, 8])

with col1:
    st.image(str(STATIC_DIR / "logo.png"), width=80)

with col2:
    st.title("Venator Cyber Threat Intelligence")

page = st.sidebar.radio("Navigator", ["How it Works", "Upload & Run", "Results"], index=0)

# --- Helpers ---
def save_uploaded_file(upload, dest: pathlib.Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as f:
        f.write(upload.getbuffer())


def preview_table(path: pathlib.Path, max_rows: int = 10, header: str | None = "infer"):
    """Read and display a small preview of CSV/XLSX/XLS.

    header: "infer" (default) respects file headers; None treats the first row as data.
    """
    try:
        suffix = path.suffix.lower()
        if suffix in (".xlsx", ".xls"):
            df = pd.read_excel(path, header=None if header is None else 0)
        elif suffix == ".csv":
            df = pd.read_csv(path, header=None if header is None else "infer")
        else:
            st.info(f"Skipping preview (unsupported extension for {path.name}).")
            return
        # For headerless single-column domain lists, label the preview column for clarity
        if header is None and df.shape[1] == 1:
            df.columns = ["domain (no header in file)"]
        st.dataframe(df.head(max_rows), use_container_width=True)
    except Exception as e:
        st.warning(f"Couldn't preview {path.name}: {e}")


def run_script(script_path: str) -> dict:
    """Run a script as a subprocess with cwd=OUTPUT_DIR and return dict of results.

    Uses the same Python interpreter as this app (sys.executable), so it respects
    your virtual environment and its dependencies.
    """
    start = time.time()
    try:
        res = subprocess.run(
            [sys.executable, script_path],
            cwd=str(OUTPUT_DIR),
            check=False,  # don't raise; we'll show stderr if it fails
            capture_output=True,
            text=True,
        )
        duration = time.time() - start
        return {
            "ok": res.returncode == 0,
            "returncode": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr,
            "seconds": round(duration, 2),
        }
    except FileNotFoundError:
        return {"ok": False, "returncode": None, "stdout": "", "stderr": "python not found in PATH", "seconds": 0}
    except Exception as e:
        return {"ok": False, "returncode": None, "stdout": "", "stderr": str(e), "seconds": 0}


def _build_xlsx(df: pd.DataFrame, *, header: bool = True) -> bytes:
    """Return an .xlsx file as bytes for download buttons."""
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, header=header)
    buf.seek(0)
    return buf.read()


def get_domains_template() -> bytes:
    """Headerless Excel: one domain per row, no header row."""
    df = pd.DataFrame([
        {"client": "DefendUs", "domains": "defendit.com,datahire.net,defendme.com"}, 
        {"client": "Total Power", "domains": "totalpower,com,totalpower.org"}, 
        ], columns=["client", "domains"])
    # Write without headers
    return _build_xlsx(df, header=True)


def get_emails_template() -> bytes:
    """Emails template with explicit columns required by darkweb_monitor.py."""
    df = pd.DataFrame([
        {"client": "DefendUs", "personal_emails": "alice@gmail.com,bob@gmail.com,t.fidel@yahoo.com", "corporate_emails": "aalice@acme.com,bbob@acme.com"},
        {"client": "Total Power",     "personal_emails": "carol@outlook.com,lgagg@aol.com","corporate_emails": "carol@globex.com,bbobb@globex.com"},
    ], columns=["client", "personal_emails", "corporate_emails"])
    return _build_xlsx(df, header=True)


# --- Upload & Run Page ---
if page == "Upload & Run":
    st.title("Upload & Run")
    st.write(
        "Upload your two spreadsheets — **company_domains.xlsx** and **company_emails.xlsx**"
    )

    c1, c2 = st.columns(2)
    with c1:
        emails_up = st.file_uploader(
            "Upload **company_emails.xlsx**",
            type=["xlsx"], key="emails",
        )
        if emails_up is not None:
            emails_ext = pathlib.Path(emails_up.name).suffix.lower()
            emails_dest = DATA_DIR / f"company_emails{emails_ext}"
            save_uploaded_file(emails_up, emails_dest)
            st.success(f"Saved as {emails_dest.relative_to(BASE_DIR)}")
            preview_table(emails_dest, header="infer")
        else:
            st.info("No 'company_emails' file uploaded yet.")

    with c2:
        domains_up = st.file_uploader(
            "Upload **company_domains.xlsx**",
            type=["xlsx"], key="domains",
        )
        if domains_up is not None:
            domains_ext = pathlib.Path(domains_up.name).suffix.lower()
            domains_dest = DATA_DIR / f"company_domains{domains_ext}"
            save_uploaded_file(domains_up, domains_dest)
            st.success(f"Saved as {domains_dest.relative_to(BASE_DIR)}")
            # Preview treating first row as data (no header)
            preview_table(domains_dest, header=None)
        else:
            st.info("No 'company_domains' file uploaded yet.")

    st.divider()

    st.subheader("Run Scripts")
    st.write("Results will be located on the Results page. Don't leave this page.")

    c3, c4, c5 = st.columns(3)
    with c3:
        if st.button("▶ Find dark web leaks tied to emails"):
            with st.spinner("Running..."):
                res = run_script(SCRIPTS_DIR / "darkweb_monitor.py")
            st.toast(
            	f"Script finished in {res['seconds']}s (code {res['returncode']})",
            	icon="✅" if res["ok"] else "⚠️"
        	)
            with st.expander("Script logs"):
                st.code(res["stdout"] or "<no stdout>", language="bash")
                if res["stderr"]:
                    st.error(res["stderr"])

    with c4:
        if st.button("▶ Find malicious domain permutations"):
            with st.spinner("Running..."):
                res = run_script(SCRIPTS_DIR / "domain_permutations.py")
            st.toast(f"Script finished in {res['seconds']}s (code {res['returncode']})", icon="✅" if res["ok"] else "⚠️")
            with st.expander("Script logs"):
                st.code(res["stdout"] or "<no stdout>", language="bash")
                if res["stderr"]:
                    st.error(res["stderr"])

    with c5:
        if st.button("▶️ Run All"):
            with st.spinner("Running all..."):
                res1 = run_script(SCRIPTS_DIR / "domain_permutations.py")
                res2 = run_script(SCRIPTS_DIR / "darkweb_monitor.py")
            st.toast(f"1/2 Scripts finished in {res1['seconds']}s (code {res1['returncode']})", icon="✅" if res1["ok"] else "⚠️")
            st.toast(f"2/2 Scripts finished in {res2['seconds']}s (code {res2['returncode']})", icon="✅" if res2["ok"] else "⚠️")
            with st.expander("Both scripts logs"):
                st.subheader("Script")
                st.code(res1["stdout"] or "<no stdout>", language="bash")
                if res1["stderr"]:
                    st.error(res1["stderr"])
                st.subheader("Script")
                st.code(res2["stdout"] or "<no stdout>", language="bash")
                if res2["stderr"]:
                    st.error(res2["stderr"])

# --- Results Page ---
elif page == "Results":
    st.title("Results")
    files = sorted(
        glob.glob(str(OUTPUT_DIR / "*.xls*")),
        key=lambda p: os.path.getmtime(p),
        reverse=True,
    )

    if not files:
        st.info("No output files found yet. Run a script on the Upload & Run page.")
    else:
        for path in files:
            p = pathlib.Path(path)
            mod = datetime.fromtimestamp(os.path.getmtime(p)).strftime("%Y-%m-%d %H:%M:%S")
            with st.container(border=True):
                st.subheader(p.name)
                st.caption(f"Saved: {p.relative_to(BASE_DIR)} • Modified: {mod}")

                # Download button
                try:
                    data = p.read_bytes()
                    st.download_button(
                        label="⬇️ Download",
                        data=data,
                        file_name=p.name,
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                        if p.suffix.lower() == ".xlsx" else "application/vnd.ms-excel",
                    )
                except Exception as e:
                    st.warning(f"Couldn't read file for download: {e}")
                try:
                        if st.button(f"🗑️ Delete {p.name}"):
                             p.unlink()  # deletes the file
                             st.success(f"{p.name} deleted successfully!")
                except FileNotFoundError:
                        st.warning(f"{p.name} not found.")
                except Exception as e:
                        st.error(f"Couldn't delete file: {e}")
                # Preview top rows
                try:
                    if p.suffix.lower() in (".xlsx", ".xls"):
                        df = pd.read_excel(p)
                    elif p.suffix.lower() == ".csv":
                        df = pd.read_csv(p)
                    else:
                        df = None
                    if df is not None:
                        st.dataframe(df.head(15), use_container_width=True)
                except Exception as e:
                    st.info(f"Preview skipped: {e}")

    st.divider()
# --- How it works Page ---
elif page == "How it Works":
    st.title("How it Works")
    st.image(STATIC_DIR / "domain_main.png", caption="Finding Domains that are staging for Phishing employees or customers", use_container_width=True)
    st.image(STATIC_DIR / "email_main.png", caption="Finding personal or company emails linked to leaked data", use_container_width=True)
    st.markdown(
        """
1) Upload two spreadsheets from "Upload and Run" tab: one with personal and/or company **emails** and one with company-owned **domains**. Download the templates below.  
2) Run two existing CTI Python scripts (you provide them) with a click.  
3) See results in "Results" tab or download the Excel outputs generated.

Note: Support for multiple clients included, API keys are free + Have I Been Pwned is optional and extremely cheap using the basic version which is $5/month. Check README on github for API instructions.

**Scripts**
- **Domain Permutations Script** — takes `company_domains.xlsx` and generates permutations found for each active domain (has mx record) with enrichment. Useful for detected threat actors staged to phish your employees or customers.   
  [📄 View documentation](https://medium.com/@sam.rothlisberger/phishnet-cybersquatting-hunting-with-python-and-apis-7c9759beccc6)

- **Darkweb Monitor Script** — takes `company_emails.xlsx` and searches for data leaks related to personal or corporate emails (PII, names, passwords, etc.). Useful for detecting data leaks for employees and taking action before they become bigger issues.   
  [📄 View documentation](https://medium.com/@sam.rothlisberger/independent-dark-web-data-breach-query-with-python-a4d073effbc7) """    

)

    st.divider()
    st.subheader("Download templates")
    col1, col2 = st.columns(2)

    with col1:
        st.write("**Domains** template")
        st.download_button(
            label="⬇️ Download",
            data=get_domains_template(),
            file_name="company_domains.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

    with col2:
        st.write("**Emails** template")
        st.download_button(
            label="⬇️ Download",
            data=get_emails_template(),
            file_name="company_emails.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
