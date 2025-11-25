# 🔍 Vscanner: Vulnerability Scanner

Vscanner is a lightweight, extensible vulnerability scanner built using Python, Nmap, and SearchSploit. It leverages containerization (Docker) and DevOps principles (CI/CD using GitHub Actions) to offer efficient vulnerability scanning and exploit matching in modern development pipelines.

---

## 📦 Features

- Aggressive port scanning using `Nmap`
- Version detection and service enumeration
- Exploit lookup via `SearchSploit` (Exploit-DB)
- Dockerized environment (based on Kali Linux)
- CI/CD enabled with GitHub Actions
- Automated report output (scan_report.txt)

---

## 🛠️ Prerequisites

To run the scanner locally (outside Docker), install the following:
```
apt update && apt upgrade -y
apt install python3 -y
apt install pipx -y
pipx ensurepath
pipx install python-nmap
apt install python3-pip -y
pip3 install python-nmap --break-system-packages
apt install nmap -y
apt install exploitdb -y
```

---

## 🐍 Running Locally (Non-Docker)

Clone the repo:

```
git clone https://github.com/YourUsesurendra1601/Vscanner.git
cd Vscanner
```

Install Python dependencies:

```
pip install -r requirements.txt
```


Start the scanner:

```
python3 scanner.py
```


---

## 🐳 Running with Docker

Build the Docker image:
```
docker build -t vscanner .
```

Run the scanner in an interactive container:
```
docker run -it vscanner /bin/bash
```


After scan completion, you can access the `scan_report.txt` inside the container.

---

## 🚀 CI/CD Integration

This project uses GitHub Actions for continuous integration. Every push runs:

- Lint checks
- Dependency validation
- Docker build verification
- Scanner execution
- Report artifact upload

CI/CD is defined in `.github/workflows/ci.yml`.

---

## 📁 Project Structure

```
├── .dockerignore
├── .github/
│   └── workflows/
│       └── ci.yml
├── Dockerfile
├── requirements.txt
├── scanner.py
└── README.md

```
## License 📜

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. ⚖️
