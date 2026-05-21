FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV KALI_PKG=kali-linux-headless

RUN apt update -q --fix-missing && apt upgrade -y \
    && apt install -y --no-install-recommends sudo wget curl openssh-server locales xxd iputils-ping \
    && sed -i 's/^# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && locale-gen \
    && apt install -y --no-install-recommends ${KALI_PKG} \
    && apt-get remove -y hashcat-data || true

RUN useradd -m -s /bin/bash -G sudo user \
    && echo 'root:root' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

RUN pip3 install --break-system-packages pycryptodome \
    && mkdir /root/scripts \
    && setcap -r /usr/lib/nmap/nmap

# Metasploit 6.4.126-dev has a bug for the whole http module, the patch described in 
# issue #21328 is applied conditionally so future builds don't get affected.
# https://github.com/rapid7/metasploit-framework/issues/21328#issuecomment-4329102732
COPY patch/http_cookie_jar.rb /tmp/http_cookie_jar.rb
RUN if msfconsole --version 2>&1 | grep -q '6.4.126-dev'; then \
        echo 'Patching Metasploit 6.4.126-dev'; \
        cp /tmp/http_cookie_jar.rb /usr/share/metasploit-framework/lib/msf/core/exploit/remote/http/http_cookie_jar.rb; \
    fi

COPY adapted_exploits/openssl_heartbleed.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/ssl/openssl_heartbleed.rb
COPY adapted_exploits/geoserver_unauth_rce_cve_2024_36401.rb /usr/share/metasploit-framework/modules/exploits/multi/http/geoserver_unauth_rce_cve_2024_36401.rb
COPY adapted_exploits/log4shell_scanner.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/http/log4shell_scanner.rb

WORKDIR "/root"