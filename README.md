# NTLM scrutinizer

## Disclaimer

It's only for education purposes.

Avoid using it on production AD.

Neither contributor incur any responsibility for any using it.



## Functionality

Based on [impacket](https://github.com/SecureAuthCorp/impacket) and [hashcat](https://github.com/hashcat/hashcat), the tool provides the following functions:

- Dump NTLM-hashes from AD and run an instance for bruting.
- Re-run a broken instance from the restore file by session name.
- Get information about a running instance by session name.
- Get information about all running instances.
- Get bruted credentials by session name.
- Run benchmark for bruting.

Check out detailed information about arguments and methods in Swagger.



## How to test it

### Test environment

The information below provided for:

- Python 3.10.5

- Ubuntu Ubuntu 20.04.4 LTS

  

### Preparations for run

Install hashcat:

```
sudo apt update
sudo apt install hashcat
```



Download the [source](https://github.com/ST1LLY/ntlm-scrutinizer) and unpack it.



Create Python virtual environment and install dependencies from requirements.txt:

```
pip install -r .\requirements.txt
```



Put in files/dictionaries a necessary dictionary, ex. [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt).

Put in files/rules a necessary rule, ex. [InsidePro-PasswordsPro.rule](https://github.com/hashcat/hashcat/blob/master/rules/InsidePro-PasswordsPro.rule).



Open project folder and run app:

```
 uvicorn app:app --reload --host 0.0.0.0 --port 5000
```



Open Swagger on http://localhost:5000/docs

Open API specification on http://localhost:5000/redoc



