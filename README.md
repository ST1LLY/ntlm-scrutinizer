It's README.md

Tested on:

Python 3.8.10

Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-89-generic x86_64)



How to run tests:

Extract sources.

```
python3 -m venv venv
```

```
source venv/bin/activate
```

```
pip install -r requirements.txt
```



put to temp folder file with hashes, file with rules, dictionary file. 



Run test app:

```
export FLASK_ENV=production
export FLASK_APP=app.py
flask run --host=0.0.0.0 --port=5000
```



Open http://127.0.0.1:5000/api/



Use /tests/run-instance to run instance

Use /tests/instance-info to get info about run instance. Use session name from output /tests/run-instance

Use /tests/all-instances-info to get info about all run instances

Use /tests/dump-and-brute-ntlm to dump and then brute ntlm by auto for all users from AD or a certain one

Use /tests/run-benchmark to run the benchmark as hashcat -b -m 1000



TODO: Add a necessary content

