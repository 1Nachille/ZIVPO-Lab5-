# ZIVPO-Lab5-
# Лабораторная работа 5
## SAST
### Анализ инструментом Fortify
Результаты сканирования:
<img width="2556" height="1386" alt="Screenshot 2025-12-14 214809" src="https://github.com/user-attachments/assets/48f0e6c6-a162-4347-896e-63a578087765" />
Описание уязввимости:
Abstract:

Hardcoded encryption keys could compromise system security in a way that is not easy to remedy.


Explanation:

It is never a good idea to hardcode an encryption key. Not only does hardcoding an encryption key allow all of the project's developers to view the encryption key, it also makes fixing the problem extremely difficult. After the code is in production, a software patch is required to change the encryption key. If the account protected by the encryption key is compromised, the owners of the system must choose between security and availability.


Example 1: The following code uses a hardcoded encryption key to encrypt information:

...
from Crypto.Ciphers import AES
encryption_key = b'_hardcoded__key_'
cipher = AES.new(encryption_key, AES.MODE_CFB, iv)
msg = iv + cipher.encrypt(b'Attack at dawn')
...


This code will run successfully, but anyone who has access to it will have access to the encryption key. After the program ships, there is likely no way to change the hardcoded encryption key _hardcoded__key_ unless the program is patched. A devious employee with access to this information can use it to compromise data encrypted by the system.




Instance ID: 51DD573C9D1FF439DECD37FE4F612F52

Priority Metadata Values:

	IMPACT: 3.0

	LIKELIHOOD: 2.4

Legacy Priority Metadata Values:

	SEVERITY: 4.0

	CONFIDENCE: 5.0
### Анализ инструментом Bandit
Результаты сканирования:
  Run started:2025-12-14 17:26:13.132028+00:00

Test results:
>> Issue: [B403:blacklist] Consider possible security implications associated with pickle module.
   Severity: Low   Confidence: High
   CWE: CWE-502 (https://cwe.mitre.org/data/definitions/502.html)
   More Info: https://bandit.readthedocs.io/en/1.9.2/blacklists/blacklist_imports.html#b403-import-pickle
   Location: ./vulnerable_app.py:7:0
6	import os
7	import pickle
8	import subprocess

--------------------------------------------------
>> Issue: [B404:blacklist] Consider possible security implications associated with the subprocess module.
   Severity: Low   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.2/blacklists/blacklist_imports.html#b404-import-subprocess
   Location: ./vulnerable_app.py:8:0
7	import pickle
8	import subprocess
9	from urllib.parse import urlparse

--------------------------------------------------
>> Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'supersecretkey'
   Severity: Low   Confidence: Medium
   CWE: CWE-259 (https://cwe.mitre.org/data/definitions/259.html)
   More Info: https://bandit.readthedocs.io/en/1.9.2/plugins/b105_hardcoded_password_string.html
   Location: ./vulnerable_app.py:12:17
11	app = Flask(__name__)
12	app.secret_key = 'supersecretkey'  # Слабый секретный ключ
13	

--------------------------------------------------
>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
   Severity: Medium   Confidence: Low
   CWE: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
   More Info: https://bandit.readthedocs.io/en/1.9.2/plugins/b608_hardcoded_sql_expressions.html
   Location: ./vulnerable_app.py:43:18
42	        
43	        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
44	        c.execute(query)

--------------------------------------------------
>> Issue: [B301:blacklist] Pickle and modules that wrap it can be unsafe when used to deserialize untrusted data, possible security issue.
   Severity: Medium   Confidence: High
   CWE: CWE-502 (https://cwe.mitre.org/data/definitions/502.html)
   More Info: https://bandit.readthedocs.io/en/1.9.2/blacklists/blacklist_calls.html#b301-pickle
   Location: ./vulnerable_app.py:166:19
165	            
166	            data = pickle.loads(bytes.fromhex(user_data))
167	            flash('Profile updated!', 'success')

--------------------------------------------------
>> Issue: [B602:subprocess_popen_with_shell_equals_true] subprocess call with shell=True identified, security issue.
   Severity: High   Confidence: High
   CWE: CWE-78 (https://cwe.mitre.org/data/definitions/78.html)
   More Info: https://bandit.readthedocs.io/en/1.9.2/plugins/b602_subprocess_popen_with_shell_equals_true.html
   Location: ./vulnerable_app.py:185:17
184	    try:
185	        result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
186	    except:

--------------------------------------------------
>> Issue: [B113:request_without_timeout] Call to requests without timeout
   Severity: Medium   Confidence: Low
   CWE: CWE-400 (https://cwe.mitre.org/data/definitions/400.html)
   More Info: https://bandit.readthedocs.io/en/1.9.2/plugins/b113_request_without_timeout.html
   Location: ./vulnerable_app.py:206:23
205	            import requests
206	            response = requests.get(url)
207	            content = response.text[:1000]  # Ограничим вывод

--------------------------------------------------
>> Issue: [B201:flask_debug_true] A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.
   Severity: High   Confidence: Medium
   CWE: CWE-94 (https://cwe.mitre.org/data/definitions/94.html)
   More Info: https://bandit.readthedocs.io/en/1.9.2/plugins/b201_flask_debug_true.html
   Location: ./vulnerable_app.py:256:4
255	    # Запуск без debug в продакшене, но для тренировок оставим
256	    app.run(debug=True, host='0.0.0.0', port=5000)

--------------------------------------------------
>> Issue: [B104:hardcoded_bind_all_interfaces] Possible binding to all interfaces.
   Severity: Medium   Confidence: Medium
   CWE: CWE-605 (https://cwe.mitre.org/data/definitions/605.html)
   More Info: https://bandit.readthedocs.io/en/1.9.2/plugins/b104_hardcoded_bind_all_interfaces.html
   Location: ./vulnerable_app.py:256:29
255	    # Запуск без debug в продакшене, но для тренировок оставим
256	    app.run(debug=True, host='0.0.0.0', port=5000)

--------------------------------------------------

Code scanned:
	Total lines of code: 195
	Total lines skipped (#nosec): 0
	Total potential issues skipped due to specifically being disabled (e.g., #nosec BXXX): 0

Run metrics:
	Total issues (by severity):
		Undefined: 0
		Low: 3
		Medium: 4
		High: 2
	Total issues (by confidence):
		Undefined: 0
		Low: 2
		Medium: 3
		High: 4
Files skipped (0):
