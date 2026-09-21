FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV KALI_PKG=kali-linux-headless

RUN apt update -q --fix-missing && apt upgrade -y \
    && apt install -y --no-install-recommends \
        sudo wget curl openssh-server locales xxd iputils-ping python3-pip python3-venv default-jdk \
    && sed -i 's/^# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && locale-gen \
    && apt install -y --no-install-recommends ${KALI_PKG} \
    && apt-get remove -y hashcat-data || true \
    && rm -rf /var/lib/apt/lists/*

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

WORKDIR "/root/tools/"

# CVE VM7 (Log4J) needs an LDAP server to perform exploitation but the machine 
# has no internet connection
COPY adapted_exploits/ldap_server.py /root/tools/ldap_server.py
RUN python3 -m venv /root/tools/.venv \
    && /root/tools/.venv/bin/pip install ldaptor \
    && apt-get purge -y --auto-remove python3-pip

WORKDIR "/root"