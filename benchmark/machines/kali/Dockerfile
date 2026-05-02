FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV KALI_PKG=kali-linux-headless

RUN apt update -q --fix-missing && apt upgrade -y \
    && apt install -y --no-install-recommends sudo wget curl openssh-server locales xxd \
    && sed -i 's/^# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && locale-gen \
    && apt install -y --no-install-recommends ${KALI_PKG} \
    && apt-get remove -y hashcat-data || true

RUN useradd -m -s /bin/bash -G sudo user \
    && echo 'root:root' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

RUN pip3 install --break-system-packages pycryptodome \
    && mkdir /root/scripts \
    && setcap -r /usr/lib/nmap/nmap

COPY adapted_exploits/openssl_heartbleed.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/ssl/openssl_heartbleed.rb
COPY adapted_exploits/geoserver_unauth_rce_cve_2024_36401.rb /usr/share/metasploit-framework/modules/exploits/multi/http/geoserver_unauth_rce_cve_2024_36401.rb
COPY adapted_exploits/log4shell_scanner.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/http/log4shell_scanner.rb

WORKDIR "/root"