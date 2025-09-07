
FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=nethounddashboard.settings \
    XML_BASE=/opt/xml \
    DISPLAY=:0

# Install system dependencies in a single layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-nmap \
    python3-pil \
    python3-tk \
    python3-pil.imagetk \
    curl \
    wget \
    git \
    libssl-dev \
    vim \
    nmap \
    tzdata \
    nano \
    unzip \
    dpkg \
    apt-utils \
    net-tools


# Create necessary directories and set permissions
RUN mkdir -p /opt/xml /opt/notes && \
    chmod 755 /opt/xml

# Install RustScan
RUN wget -P /opt/ https://github.com/bee-san/RustScan/releases/download/2.4.1/x86_64-linux-rustscan.tar.gz.zip && \
    cd /opt/ && \ 
    unzip x86_64-linux-rustscan.tar.gz.zip && \
    tar xf x86_64-linux-rustscan.tar.gz && \
    mv rustscan /usr/local/bin/ && \
    chmod +x /usr/local/bin/rustscan && \
    rm x86_64-linux-rustscan.tar.gz.zip x86_64-linux-rustscan.tar.gz

WORKDIR /opt/nethounddashboard


COPY . .

# Install Python dependencies
RUN if [ -f /usr/lib/python*/EXTERNALLY-MANAGED ]; then \
        rm -f /usr/lib/python*/EXTERNALLY-MANAGED; \
    fi && \
    python3 -m pip install --no-cache-dir --break-system-packages --ignore-installed -r requirements.txt && \
    python3 manage.py migrate

# Setup script files and permissions
COPY docker/tzdata.sh /root/tzdata.sh
COPY docker/startup.sh /startup.sh

RUN chmod +x /root/tzdata.sh /startup.sh && \
    ln -s /opt/nethounddashboard/nethoundreport/token.py /root/token && \
    chmod +x /root/token && \
    mkdir -p /.local/share && \
    chmod 777 /.local /.local/share


VOLUME ["/opt/xml"]

EXPOSE 8000


HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8000/ || exit 1

ENTRYPOINT ["bash", "/startup.sh"]
