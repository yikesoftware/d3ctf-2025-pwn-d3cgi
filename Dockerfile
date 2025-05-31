FROM ubuntu:24.04

RUN echo "" > /etc/apt/sources.list.d/ubuntu.sources && \
    echo "Types: deb" >> /etc/apt/sources.list.d/ubuntu.sources && \
    echo "URIs: http://mirrors.aliyun.com/ubuntu/" >> /etc/apt/sources.list.d/ubuntu.sources && \
    echo "Suites: noble noble-updates noble-security" >> /etc/apt/sources.list.d/ubuntu.sources && \
    echo "Components: main restricted universe multiverse" >> /etc/apt/sources.list.d/ubuntu.sources && \
    echo "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg" >> /etc/apt/sources.list.d/ubuntu.sources

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
    libc6:i386 zlib1g:i386 gcc-multilib g++-multilib \
    build-essential libpcre3-dev libssl-dev zlib1g-dev wget ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf && \
    mkdir -p /home/ctf && \
    mkdir -p /home/ctf/www

WORKDIR /home/ctf

COPY files/ /home/ctf/
RUN chmod +x /home/ctf/run.sh && \
    chmod +x /home/ctf/lighttpd && \
    chmod +x /home/ctf/challenge && \
    chown -R ctf:ctf /home/ctf

EXPOSE 8888
EXPOSE 9999
CMD ["/home/ctf/startup.sh"]
