# CVE-2021-41773 / CVE-2021-42013 — Vulnerable Apache HTTP Server
#
# Base image is pinned to the exact vulnerable release. mod_cgi is enabled and
# /cgi-bin/ is aliased with "Require all granted" — a configuration pattern
# that was common in real deployments in 2021 and is what turns the path
# traversal bug into full remote code execution (per the official advisory).
FROM httpd:2.4.49

# Enable the CGI module (disabled by default in the base image)
RUN sed -i \
    -e 's/#LoadModule cgid_module/LoadModule cgid_module/' \
    /usr/local/apache2/conf/httpd.conf

# The stock httpd.conf ships a blanket "Require all denied" on <Directory />.
# That default *would* stop the traversal from reaching anything outside the
# cgi-bin alias even after the normalization bug fires. Real-world hosts hit
# by this CVE commonly lacked that hardening (or had it overridden by a
# broader vhost config) — that's the exact config gap this lab reproduces,
# and it's documented as an explicit assumption in docs/research.md.
RUN sed -i '0,/Require all denied/s//Require all granted/' \
    /usr/local/apache2/conf/httpd.conf

# A plain, non-CGI static alias. This is the target for the file-read half
# of the PoC: traversal escapes here into arbitrary files that Apache just
# serves as-is, instead of trying (and failing) to execute them as CGI.
RUN mkdir -p /usr/local/apache2/htdocs/static
RUN printf '\n\
Alias /static/ /usr/local/apache2/htdocs/static/\n\
<Directory "/usr/local/apache2/htdocs/static">\n\
    Require all granted\n\
</Directory>\n' >> /usr/local/apache2/conf/httpd.conf

# Add an insecure cgi-bin alias + directory block.
# NOTE: this Require all granted is the intentionally-vulnerable piece:
# it is what allows the path-traversal-normalized request to reach the
# filesystem/CGI handler instead of being blocked by access control.
RUN printf '\n\
ScriptAlias /cgi-bin/ /usr/local/apache2/cgi-bin/\n\
<Directory "/usr/local/apache2/cgi-bin">\n\
    AllowOverride None\n\
    Options +ExecCGI\n\
    AddHandler cgi-script .sh .cgi\n\
    Require all granted\n\
</Directory>\n' >> /usr/local/apache2/conf/httpd.conf

# A harmless CGI script, standing in for "some legitimate CGI app" that a
# real site would have deployed. Its presence is what CVE-2021-42013/41773
# leverage to reach bash via the CGI handler.
COPY cgi-bin/test.sh /usr/local/apache2/cgi-bin/test.sh
RUN chmod +x /usr/local/apache2/cgi-bin/test.sh

EXPOSE 80
