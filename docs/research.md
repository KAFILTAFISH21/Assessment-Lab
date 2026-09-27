# CVE Research — CVE-2021-41773 & CVE-2021-42013

## Affected product and versions
- **Product:** Apache HTTP Server (httpd)
- **Vulnerable versions:** 2.4.49 (CVE-2021-41773), and 2.4.49/2.4.50 (CVE-2021-42013,
  the bypass of the incomplete first fix)
- **Fixed version:** 2.4.51

## Severity and CVSS
- **CVE-2021-41773:** CVSS v3.1 base score **7.5 (High)** for the path traversal /
  information disclosure case, escalating to **critical impact** when combined with
  CGI execution (effectively RCE, CVSS 9.8 in that configuration).
- **CVE-2021-42013:** CVSS v3.1 base score **9.8 (Critical)** — NVD classifies the
  bypass itself as enabling RCE directly since it was published with the CGI/RCE
  angle already understood.
- Both were **confirmed exploited in the wild** within days of disclosure (October 2021).

## Vulnerability type / CWE
- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory ("Path
  Traversal")
- Secondary: **CWE-78** (OS Command Injection) is reached when the traversal is
  combined with an aliased, CGI-enabled directory, since the traversal is used to
  invoke `/bin/sh` directly.

## Root cause
Apache 2.4.49 introduced a change to the URL path-normalization code used when
mapping a request URI to a filesystem path for `Alias`/`ScriptAlias`-defined
locations (the code path is in `server/util.c` / `ap_normalize_path` and the
`map_to_storage` hooks used by `mod_cgi`/`mod_alias`).

Before this change, Apache canonicalized (`.`/`..`) segments in the URL *before*
running access-control checks on the resulting directory, so a request like
`/cgi-bin/../../../../etc/passwd` was already resolved and blocked/matched to
`/etc/passwd`, outside of the aliased directory, and denied.

The 2.4.49 change altered the order/logic so that **URL-encoded** dot segments
(`%2e` for `.`) were left un-normalized at the point access control ran against
the `Alias`/`ScriptAlias` path, but were **later decoded** by the OS/handler when
actually opening the file or invoking the CGI handler. This meant:
- A request is matched against the `cgi-bin` alias and passes its access checks
  (because the raw string still looks like it's inside `cgi-bin`).
- The encoded dots are decoded afterward, and the final filesystem lookup walks
  **outside** the aliased directory.

If the resulting path is not independently protected by a blanket
`Require all denied` (the default top-level `<Directory />` block in a stock
`httpd.conf`), the request succeeds — either as a plain file read (path
traversal → file disclosure) or, if the resolved path points at an executable
and the directory has `Options +ExecCGI`/`mod_cgi` enabled, as **command
execution** through the CGI handler.

The first patch (2.4.50) only stripped/normalized the **single**-encoded form
(`%2e`). Researchers found that a **double URL-encoded** sequence
(`%%32%65`, which decodes to `%2e` and then again to `.`) survived the new
filter and reached the vulnerable code path a second time — this incomplete fix
is tracked separately as **CVE-2021-42013**.

## Attack prerequisites
- **Privileges required:** None — unauthenticated, remote.
- **User interaction:** None.
- **Network position:** Direct network access to the HTTP(S) port.
- **Configuration prerequisite:** The vulnerable version alone only yields file
  disclosure of files readable by the Apache worker process, *and only if* the
  targeted path is not covered by a `Require all denied` directory block
  somewhere in the effective config. RCE additionally requires `mod_cgi`
  (`cgid_module`) to be loaded and a `ScriptAlias`'d, CGI-enabled directory to
  traverse from (e.g., a typical `/cgi-bin/`) — a very common production
  pattern in 2021, which is why this was assessed as high real-world impact
  despite the config caveat.

## Attack surface and impact
- **Attack surface:** Any URL path served by an `Alias`/`ScriptAlias` directive
  (most commonly `/cgi-bin/`).
- **Impact:**
  - Arbitrary file **read** of any file the Apache worker user can access
    (source code, credentials in config files, `/etc/passwd`, etc.)
  - **Remote code execution** as the Apache worker user (commonly `www-data`
    or similar) when CGI is enabled for the aliased path.

## Public advisories, commits, and references
- Apache Security Advisory (CVE-2021-41773):
  https://httpd.apache.org/security/vulnerabilities_24.html
- NVD entry: https://nvd.nist.gov/vuln/detail/CVE-2021-41773
- NVD entry (bypass): https://nvd.nist.gov/vuln/detail/CVE-2021-42013
- Apache httpd fix commit (2.4.50 partial fix) and follow-up fix in 2.4.51,
  referenced from the official changelog: https://downloads.apache.org/httpd/CHANGES_2.4
- Public PoCs / write-ups used to cross-check the exploit primitives in this
  lab (credited per assignment instructions, no code copied verbatim):
  - Ash Daulton and the cPanel Security Team (credited by Apache's own advisory
    as reporters of CVE-2021-41773)
  - Multiple independent public GitHub PoC repositories reproducing the same
    `.%2e` / `%%32%65` traversal payload structure used here.

## Assumptions and limitations documented for this lab
- The lab intentionally configures `cgi-bin` with `Require all granted` and a
  CGI script present, mirroring common real-world deployments. This is
  explicitly called out as an assumption, since a "hardened by default" Apache
  install (with a global `Require all denied` and no CGI aliasing) would only
  be exploitable for a narrower file-disclosure case, not RCE.
- The lab uses the official Docker Hub `httpd` images pinned to `2.4.49` and
  `2.4.51` rather than compiling from source, since the vulnerability lives in
  the served binary/config behavior, not anything OS-packaging-specific.
