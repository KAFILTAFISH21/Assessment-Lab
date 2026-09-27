# CVE 2021 41773 / CVE 2021 42013 Apache HTTP Server Path Traversal and RCE Lab

A self contained Docker based lab for reproducing, exploiting, detecting, and remediating the Apache HTTP Server path traversal vulnerability disclosed in October 2021.

This lab covers both CVE 2021 41773 and the patch bypass tracked as CVE 2021 42013. It includes a vulnerable Apache 2.4.49 instance and a patched Apache 2.4.51 instance so the behavior can be tested and compared in a controlled environment.

The detailed technical research, including the root cause, CWE, CVSS information, and advisories, is available in `docs/research.md`.

The source for the technical blog is available in `docs/blog_source.md`, along with the submitted PDF.

## Prerequisites

You will need either:

* Docker Engine with Docker Compose v2
* Podman with podman-compose

## Lab Environment

| Component      | Vulnerable Instance | Patched Instance |
| -------------- | ------------------- | ---------------- |
| Apache version | 2.4.49              | 2.4.51           |
| Image          | `httpd:2.4.49`      | `httpd:2.4.51`   |
| Port           | `127.0.0.1:8080`    | `127.0.0.1:8081` |
| CGI            | Enabled             | Enabled          |
| Static alias   | `/static/`          | `/static/`       |

Both instances use the same basic configuration so that the vulnerable and patched versions can be compared fairly.

The lab uses two configuration changes that are important for reproducing the vulnerability.

First, the default `Require all denied` setting under `<Directory />` is changed to `Require all granted`. This allows the traversal request to reach files outside the intended directory.

Second, a `/static/` alias is added. This provides a simple location where the file read portion of the vulnerability can be demonstrated without Apache attempting to execute the requested file as CGI.

These settings are specific to the lab and should not be considered recommended production configuration.

## 1. Start the Lab

Clone the repository and move into the project directory:

```bash
git clone <this-repo-url>
cd Assessment-Lab
```

Start both Apache containers:

```bash
docker compose up -d --build
```

Check that both containers are running:

```bash
docker compose ps
```

You can then verify the Apache versions:

```bash
curl -I http://127.0.0.1:8080/
curl -I http://127.0.0.1:8081/
```

The vulnerable instance should report Apache 2.4.49, while the patched instance should report Apache 2.4.51.

You can also verify that CGI is working:

```bash
curl http://127.0.0.1:8080/cgi-bin/test.sh
```

## 2. Reproduce the Vulnerability

The exploitation scripts are located in the `scripts/` directory.

### 2.1 Arbitrary File Read

The first part of the lab demonstrates path traversal and arbitrary file disclosure.

Run:

```bash
./scripts/exploit_path_traversal.sh 127.0.0.1:8080 /etc/passwd
```

If everything is configured correctly, the contents of `/etc/passwd` from inside the vulnerable Apache container will be displayed.

The important part here is that `/etc/passwd` is outside the `/static/` directory. The traversal vulnerability allows the request to escape the intended directory and access the file.

Try the same command against the patched instance:

```bash
./scripts/exploit_path_traversal.sh 127.0.0.1:8081 /etc/passwd
```

The patched server should reject the request with a normal HTTP error response.

### 2.2 Remote Code Execution

The second part demonstrates how the traversal vulnerability can be combined with CGI to achieve command execution.

For example:

```bash
./scripts/exploit_rce.sh 127.0.0.1:8080 "id"
```

You can also run:

```bash
./scripts/exploit_rce.sh 127.0.0.1:8080 "uname -a"
```

The command output should be returned in the HTTP response.

This shows that the issue can go beyond reading files. With CGI enabled and the required configuration in place, an attacker can reach command execution through the vulnerable path handling.

Run the same commands against the patched instance:

```bash
./scripts/exploit_rce.sh 127.0.0.1:8081 "id"
./scripts/exploit_rce.sh 127.0.0.1:8081 "uname -a"
```

The commands should fail on Apache 2.4.51.

## 3. Detect the Vulnerability

The repository also includes a detection script:

```bash
./scripts/detect.sh 127.0.0.1:8080
```

Expected result:

```text
VULNERABLE
```

Now test the patched instance:

```bash
./scripts/detect.sh 127.0.0.1:8081
```

Expected result:

```text
NOT vulnerable
```

The detection script uses two checks.

The first is a passive check of the `Server` response header to identify the Apache version.

The second is an active but harmless request that attempts to access Apache's own configuration file through the same traversal mechanism. This helps confirm actual exploitability instead of relying only on the version number.

Version based detection alone is not always reliable in real environments because server banners can be hidden or modified.

## 4. Remediation

The recommended fix is to upgrade Apache HTTP Server to a patched version.

For this lab, the vulnerable instance uses:

```text
Apache HTTP Server 2.4.49
```

The patched instance uses:

```text
Apache HTTP Server 2.4.51
```

Apache 2.4.50 should not be considered sufficient because CVE 2021 42013 bypassed the incomplete fix introduced in 2.4.50.

To simulate replacing the vulnerable instance with the patched one:

```bash
docker compose stop vulnerable-apache
docker compose build patched-apache
docker compose up -d patched-apache
```

After replacing the instance, run the detection script again:

```bash
./scripts/detect.sh 127.0.0.1:8081
```

You can also test the traversal request:

```bash
./scripts/exploit_path_traversal.sh 127.0.0.1:8081 /etc/passwd
```

The patched server should no longer be vulnerable to the traversal technique demonstrated in this lab.

## 5. Stop the Lab

When you are finished testing, stop and remove the containers:

```bash
docker compose down
```

## Troubleshooting

### Curl cannot connect

If you see:

```text
curl: (7) Failed to connect
```

the container may still be starting.

Check the container logs:

```bash
docker compose logs vulnerable-apache
```

### The exploit does not return anything

Some versions of `curl` may normalize or encode the `%` characters used in the traversal payload.

The scripts in this repository use `--path-as-is` to prevent this behavior.

If you create your own request, make sure you use the same option.

### Port already in use

If ports `8080` or `8081` are already being used by another application, change the port mappings in `docker-compose.yml`.

### Podman socket error

If you see an error similar to:

```text
Cannot connect to the Docker daemon ... podman.sock
```

the Podman socket may not be running.

Start it with:

```bash
systemctl --user enable --now podman.socket
```

You can then run the lab again.

Alternatively, use `podman-compose` instead of Docker Compose.

## Credits

The vulnerability was originally discovered and reported by Ash Daulton and the cPanel Security Team, as documented in Apache's official security advisory.

The lab configuration and exploitation workflow were created using information from Apache's advisory and cross referenced with publicly available technical research covering the same vulnerability.

Additional technical details and references can be found in `docs/research.md`.

