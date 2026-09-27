# Remediated version of the same lab.
#
# Everything about the configuration is IDENTICAL to the vulnerable image
# (same insecure cgi-bin Require all granted, same test script) — the ONLY
# change is the base image version. This isolates the fix to what actually
# matters: Apache's path-normalization code in 2.4.51+, which closes both
# CVE-2021-41773 and the CVE-2021-42013 bypass.
FROM httpd:2.4.51

RUN sed -i \
    -e 's/#LoadModule cgid_module/LoadModule cgid_module/' \
    /usr/local/apache2/conf/httpd.conf

# Same override as the vulnerable image, kept identical on purpose so the
# ONLY difference between the two containers is the Apache version itself.
RUN sed -i '0,/Require all denied/s//Require all granted/' \
    /usr/local/apache2/conf/httpd.conf

RUN mkdir -p /usr/local/apache2/htdocs/static
RUN printf '\n\
Alias /static/ /usr/local/apache2/htdocs/static/\n\
<Directory "/usr/local/apache2/htdocs/static">\n\
    Require all granted\n\
</Directory>\n' >> /usr/local/apache2/conf/httpd.conf

RUN printf '\n\
ScriptAlias /cgi-bin/ /usr/local/apache2/cgi-bin/\n\
<Directory "/usr/local/apache2/cgi-bin">\n\
    AllowOverride None\n\
    Options +ExecCGI\n\
    AddHandler cgi-script .sh .cgi\n\
    Require all granted\n\
</Directory>\n' >> /usr/local/apache2/conf/httpd.conf

COPY cgi-bin/test.sh /usr/local/apache2/cgi-bin/test.sh
RUN chmod +x /usr/local/apache2/cgi-bin/test.sh

EXPOSE 80
