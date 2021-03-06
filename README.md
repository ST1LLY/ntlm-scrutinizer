# NTLM scrutinizer

It is part of the [dc-sonar](https://github.com/ST1LLY/dc-sonar) project.

## Disclaimer

It's only for education purposes.

Avoid using it on production AD.

Neither contributor incur any responsibility for any using it.

## Functionality

Based on [impacket](https://github.com/SecureAuthCorp/impacket) and [hashcat](https://github.com/hashcat/hashcat), the tool provides the following functions:

- Dump NTLM-hashes from AD
- Run bruting of dumped NTLM-hashes.
- Re-run a broken instance of bruting from the restore file by session name.
- Get information about a running dump instance by session name.
- Get information about a running brute instance by session name.
- Get information about all running brute instances.
- Get bruted credentials by brute session name.
- Run benchmark of bruting.

Check out detailed information about arguments and methods in Swagger.

## How to test it

### Ubuntu

#### Test environment

The information below provided for:

- Python 3.10.5

- Ubuntu Ubuntu 20.04.4 LTS

  

#### Preparations for run

Clone [ntlm-scrutinizer](https://github.com/ST1LLY/ntlm-scrutinizer) if directory ntlm-scrutinizer does not exist:

```bash
git clone https://github.com/ST1LLY/dc-sonar-workers-layer.git
```

Install hashcat:

```bash
sudo apt update
sudo apt install hashcat
```

Create venv:

```shell
python3.10 -m venv venv-ntlm-scrut
```

Activate created venv:

```shell
source venv-ntlm-scrut/bin/activate
```

Install dependencies:

```shell
pip install -r ntlm-scrutinizer/requirements.txt
```

Open the project folder:

```
cd ntlm-scrutinizer
```

Create a self-signed certificate:

```bash
sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout dev_selfsigned.key -out dev_selfsigned.crt
```

Deactivate venv:

```
deactivate
```

### Windows

Clone [ntlm-scrutinizer](https://github.com/ST1LLY/ntlm-scrutinizer):

```bash
git clone https://github.com/ST1LLY/ntlm-scrutinizer
```

Open Powershell.

Go to the created ntlm-scrutinizer folder:

```
cd {YOUR_PATH}
```

Create Python virtual environment:

```powershell
&"C:\Program Files\Python310\python.exe" -m venv venv
```

Active venv:

```
.\venv\Scripts\Activate.ps1
```

Install pip packages:

```
pip install -r .\requirements.txt
```

### Config

Put in files/dictionaries a necessary dictionary, ex. [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt).

Put in files/rules a necessary rule, ex. [InsidePro-PasswordsPro.rule](https://github.com/hashcat/hashcat/blob/master/rules/InsidePro-PasswordsPro.rule).

Copy `configs/settings_blank.conf` to `configs/settings.conf`.

Set the params:

The param `aes_256_key` in `APP` section is being used for decryption and encryption saved passed of accounts have been bruted.

### Run

Open terminal.

Execute commands for running web app:

```shell
source venv-ntlm-scrut/bin/activate
cd ntlm-scrutinizer/
uvicorn app:app --reload --host 0.0.0.0 --port 5000 --ssl-keyfile dev_selfsigned.key --ssl-certfile dev_selfsigned.crt
```

Open Swagger on [https://localhost:5000/docs](https://localhost:5000/docs).

Open API specification on [https://localhost:5000/redoc](https://localhost:5000/redoc).
