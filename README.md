# NTLM scrutinizer

## Disclaimer

It's only for education purposes.

Avoid using it on production AD.

Neither contributor incur any responsibility for any using it.



## Functionality

Based on [impacket](https://github.com/SecureAuthCorp/impacket) and [hashcat](https://github.com/hashcat/hashcat), the tool provides the following functions:

- Run an instance of hashcat to brute NTLM-hashes and return session name. 
- Re-run a broken instance from the restore file by session name.
- Dump NTLM-hashes from AD and run an instance for bruting.
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

Create Python virtual environment and install dependencies from requirements.txt.

Put in files/dictionaries a necessary dictionary.

Put in files/rules a necessary rule.

If an early dumped NTLM file exists, then put it in files/ntlm_hashes.



Run flask app:

```
export FLASK_ENV=production
export FLASK_APP=app.py
flask run --host=0.0.0.0 --port=5000
```



Open Swagger on http://127.0.0.1:5000/api/



