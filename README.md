# auto-acme

**Automatically generate and renew HTTPS certificates using the ACME protocol (Let's Encrypt).**

`auto-acme` is a Python package that simplifies the process of obtaining and renewing HTTPS certificates for your web applications using the ACME protocol. It integrates seamlessly with popular web frameworks like Flask, Django, and FastAPI, and can be used with any Python web server that supports SSL contexts.

## Features

- **Automatic Certificate Management**: Obtain and renew certificates automatically.
- **Let's Encrypt Support**: Works with Let's Encrypt and other ACME-compatible CAs.
- **Framework Agnostic**: Use with Flask, Django, FastAPI, or any WSGI/ASGI server.
- **Simple Configuration**: Minimal setup required.
- **Certificate Storage**: Certificates are stored locally and reused until renewal is needed.

## Installation

Install `auto-acme` using pip:

```bash
pip install auto-acme
```

Or from source:

```bash
git clone https://github.com/yourusername/auto-acme.git
cd auto-acme
pip install .
```

## Usage
Basic Example with Flask

```python
from flask import Flask
import auto_acme

app = Flask(__name__)

@app.route('/')
def home():
    return "Automatic HTTPS-Certificate with auto-acme."

if __name__ == '__main__':
    acme_context = auto_acme.AcmeContext(
        certificate_path="~/.acme_certs",
        acme_url="https://acme-v02.api.letsencrypt.org/directory",
        hostname="example.com",
        agree_tos=True,
    )
    app.run(host="0.0.0.0", port=443, ssl_context=acme_context)
```

With Django

```python
from django.core.servers.basehttp import WSGIServer
import auto_acme

def run_django_with_acme():
    acme_context = auto_acme.AcmeContext(
        certificate_path="~/.acme_certs",
        acme_url="https://acme-v02.api.letsencrypt.org/directory",
        hostname="example.com",
        agree_tos=True,
    )
    server = WSGIServer(("0.0.0.0", 443), WSGIHandler(), ssl_context=acme_context)
    server.serve_forever()

if __name__ == "__main__":
    run_django_with_acme()
```

## Configuration
### Required Parameters

| Parameter          | Description |
|--------------------|-------------|
| `certificate_path` | Directory where certificates and private keys will be stored. |
| `acme_url`         | ACME server URL (e.g., Let's Encrypt staging or production). |
| `hostname`         | Domain name for which the certificate will be issued. |

### Optional Parameters

| Parameter          | Description | Default Value |
|--------------------|-------------|---------------|
| `contact`          | List of emails for ACME account registration. | `None` |
| `agree_tos`        | Automatically agree to the ACME server's terms of service. | `False` |


## How It Works

Initialization: When AcmeContext is created, it checks for existing certificates.
Certificate Request: If no valid certificate is found, it registers with the ACME server and requests a new certificate.
Challenge Handling: Automatically responds to ACME challenges (TLS-ALPN-01).
Certificate Storage: Stores the certificate and private key in the specified directory.
Renewal: Automatically renews certificates before they expire.

## Contributing
Contributions are welcome! Please follow these steps:

* Fork the repository.
* Create a new branch for your feature or bugfix.
* Write tests for your changes.
* Submit a pull request.

## License
auto-acme is licensed under the MIT License. See LICENSE for details.

## Support
For questions, issues, or feature requests, please open an issue on the GitHub repository.
