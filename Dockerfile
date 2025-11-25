FROM kalilinux/kali-rolling

# Install apt-get and required packages, then set up a venv and Python deps
RUN apt-get update && \
    apt-get full-upgrade -y && \
    apt-get install -y \
      python3 \
      python3-venv \
      python3-pip \
      nmap \
      exploitdb \
      git && \
    rm -rf /var/lib/apt/lists/*

# Create and activate virtualenv, install Python packages
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install python-nmap

# Copy your scanner script into the image
COPY scanner.py /opt/scanner.py
WORKDIR /opt

# Set the venv python as default
ENV PATH="/opt/venv/bin:$PATH"

ENTRYPOINT ["python", "scanner.py"]