# Cyber Calculator Web — English Edition

## Web project
Run: `python -m pip install -r requirements.txt` then `python app.py` and open http://127.0.0.1:5000.

## One-file Windows app
Run `build_windows_exe.bat` on a Windows PC. It creates `dist\CyberCalculatorWeb.exe` as a standalone executable, so the target Windows PC does not need Python installed.

The executable is Windows-specific. For macOS/Linux, build separately on the target OS.

## Features
Responsive cyber dashboard, Matrix animation, themes, calculator, IPv4/CIDR, Subnet, VLSM, IPv6, IP range, wildcard, bitwise, MAC, number conversion, hashes, Base64, Hex, URL encoding, entropy, UUID, checksum, JWT structure decoding, timestamp, ASCII, Regex, JSON, URL parser and unit converter.

Security features are educational/defensive.
Flask>=3.0,<4
gunicorn