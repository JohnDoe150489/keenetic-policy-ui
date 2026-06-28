<?php
/**
 * Keenetic Policy UI — PHP Backend (Entware/lighttpd).
 *
 * Single-file API handler called via lighttpd CGI for every /api/* request.
 * Routes requests by method + URI to the appropriate handler.
 *
 * Two-level auth model:
 *   1. RCI calls (this script → router) — no auth (127.0.0.1:79/rci)
 *   2. Frontend login (browser → this script) — challenge-response + JWT
 *
 * @see entware/etc/keenetic-policy-ui.conf
 */

// ── Config ────────────────────────────────────────────────────────

define('CONF_FILE', '/opt/etc/keenetic-policy-ui/keenetic-policy-ui.conf');
define('DEFAULT_POLICIES_FILE', '/opt/etc/keenetic-policy-ui/policies.json');
define('CHALLENGES_FILE', '/tmp/keenetic-policy-ui-challenges.json');
define('JWT_SECRET_FILE', '/opt/etc/keenetic-policy-ui/.jwt_secret');
define('CHALLENGE_TTL', 300); // 5 minutes

define('L_SILENT', 0);
define('L_ERROR',  1);
define('L_WARN',   2);
define('L_INFO',   3);
define('L_DEBUG',  4);

function parse_log_level(string $level): int {
  $l = strtolower($level);
  if ($l === 'silent') return L_SILENT;
  if ($l === 'error')  return L_ERROR;
  if ($l === 'warn' || $l === 'warning') return L_WARN;
  if ($l === 'debug')  return L_DEBUG;
  return L_INFO;
}

function log_msg(int $level, string $message, array $context = [], ?string $clientIp = null): void {
  global $logLevel, $logFile;
  if ($level > ($logLevel ?? L_INFO)) return;

  $labels = [L_ERROR => 'ERRO', L_WARN => 'WARN', L_INFO => 'INFO', L_DEBUG => 'DEBG'];
  $label  = $labels[$level] ?? 'INFO';
  $ts     = date('Y-m-d H:i:s');

  // Формируем сообщение без даты — дату добавляем только для файла
  $msg = "[$label]";
  if ($clientIp !== null && $level >= L_WARN) {
    $msg .= " [$clientIp]";
  }
  $msg .= " $message";
  if ($context) {
    $msg .= ' — ' . format_context($context);
  }

  // 1. Write to syslog (visible via logread on Keenetic) — без даты
  static $syslogInit = false;
  if (!$syslogInit) {
    openlog('keenetic-policy-ui', LOG_PID | LOG_NDELAY, LOG_LOCAL0);
    $syslogInit = true;
  }
  $syslogPri = ($level <= L_ERROR) ? LOG_ERR : (($level === L_WARN) ? LOG_WARNING : LOG_INFO);
  syslog($syslogPri, $msg);

  // 2. Write to file if configured — с датой в начале
  if ($logFile) {
    $line = "[$ts] $msg\n";
    $dir = dirname($logFile);
    if (!is_dir($dir)) {
      @mkdir($dir, 0755, true);
    }
    @file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);
  }
}

/**
 * Форматирует контекст в читаемый вид: key="value", key=yes/no
 * Вместо JSON-дампа выводит только то, что нужно для понимания.
 */
function format_context(array $context): string {
  $parts = [];
  foreach ($context as $key => $val) {
    if (is_bool($val)) {
      $parts[] = "$key=" . ($val ? 'yes' : 'no');
    } elseif ($val === null) {
      $parts[] = "$key=-";
    } elseif (is_string($val)) {
      $parts[] = "$key=\"$val\"";
    } else {
      $parts[] = "$key=$val";
    }
  }
  return implode(', ', $parts);
}

function load_config(): array {
  $config = [
    'router' => ['rci_url' => 'http://127.0.0.1:79'],
    'auth'   => ['enabled' => false, 'jwt_secret' => '', 'api_token' => ''],
    'app'    => ['policies_file' => DEFAULT_POLICIES_FILE, 'log_level' => 'warn', 'log_file' => ''],
  ];

  if (file_exists(CONF_FILE)) {
    $parsed = parse_ini_file(CONF_FILE, true);
    if ($parsed) {
      foreach ($config as $section => $defaults) {
        if (isset($parsed[$section])) {
          $config[$section] = array_merge($defaults, $parsed[$section]);
        }
      }
    }
  }

  return $config;
}

function get_jwt_secret(array $config): string {
  if (!empty($config['auth']['jwt_secret'])) {
    return $config['auth']['jwt_secret'];
  }
  // Auto-generate persistent secret
  if (file_exists(JWT_SECRET_FILE)) {
    return trim(file_get_contents(JWT_SECRET_FILE));
  }
  $secret = bin2hex(random_bytes(32));
  $dir = dirname(JWT_SECRET_FILE);
  if (!is_dir($dir)) {
    mkdir($dir, 0755, true);
  }
  file_put_contents(JWT_SECRET_FILE, $secret, LOCK_EX);
  chmod(JWT_SECRET_FILE, 0600);
  return $secret;
}

// ── RCI Client (no auth — 127.0.0.1:79) ──────────────────────────

define('RCI_TIMEOUT', 5);

function rci_get(string $rciUrl, string $path): array {
  $ch = curl_init($rciUrl . $path);
  curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => RCI_TIMEOUT,
    CURLOPT_CONNECTTIMEOUT => RCI_TIMEOUT,
    CURLOPT_NOSIGNAL       => 1,
  ]);
  $body = curl_exec($ch);
  $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  $curlErrno = curl_errno($ch);
  curl_close($ch);

  if ($curlErrno !== 0) {
    throw new RuntimeException("RCI GET $path failed: curl error $curlErrno");
  }
  if ($httpCode < 200 || $httpCode >= 300) {
    throw new RuntimeException("RCI GET $path failed: HTTP $httpCode");
  }

  $decoded = json_decode($body, true);
  return is_array($decoded) ? $decoded : [];
}

function rci_post(string $rciUrl, string $path, array $data): array {
  $payload = json_encode($data);
  $ch = curl_init($rciUrl . $path);
  curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST           => true,
    CURLOPT_POSTFIELDS     => $payload,
    CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
    CURLOPT_TIMEOUT        => RCI_TIMEOUT,
    CURLOPT_CONNECTTIMEOUT => RCI_TIMEOUT,
    CURLOPT_NOSIGNAL       => 1,
  ]);
  $body = curl_exec($ch);
  $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  $curlErrno = curl_errno($ch);
  curl_close($ch);

  if ($curlErrno !== 0) {
    throw new RuntimeException("RCI POST $path failed: curl error $curlErrno");
  }
  if ($httpCode < 200 || $httpCode >= 300) {
    throw new RuntimeException("RCI POST $path failed: HTTP $httpCode");
  }

  $decoded = json_decode($body, true);
  return is_array($decoded) ? $decoded : [];
}

// ── JWT (pure PHP, HS256) ────────────────────────────────────────

function base64url_encode(string $data): string {
  return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode(string $data): string {
  $remainder = strlen($data) % 4;
  if ($remainder) {
    $data .= str_repeat('=', 4 - $remainder);
  }
  return base64_decode(strtr($data, '-_', '+/'));
}

function issue_jwt(string $login, string $secret): string {
  $header  = base64url_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
  $payload = base64url_encode(json_encode([
    'login' => $login,
    'iat'   => time(),
    'exp'   => time() + 86400, // 24h
  ]));
  $signature = base64url_encode(
    hash_hmac('sha256', "$header.$payload", $secret, true)
  );
  return "$header.$payload.$signature";
}

function verify_jwt(string $token, string $secret): ?string {
  $parts = explode('.', $token);
  if (count($parts) !== 3) return null;

  [$headerB64, $payloadB64, $signatureB64] = $parts;

  // Verify signature
  $expectedSig = base64url_encode(
    hash_hmac('sha256', "$headerB64.$payloadB64", $secret, true)
  );
  if (!hash_equals($expectedSig, $signatureB64)) return null;

  // Decode payload
  $payload = json_decode(base64url_decode($payloadB64), true);
  if (!$payload || !isset($payload['login'])) return null;

  // Check expiry
  if (isset($payload['exp']) && $payload['exp'] < time()) return null;

  return $payload['login'];
}

function get_auth_user(array $config): ?string {
  $header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
  if (!preg_match('/^Bearer\s+(.+)$/i', $header, $m)) return null;
  return verify_jwt($m[1], get_jwt_secret($config));
}

function check_api_token(array $config): ?string {
  $token = $config['auth']['api_token'] ?? '';
  if ($token === '') return null;

  // Check X-API-Token header, or Authorization: Bearer <token> if it's not a JWT
  $apiHeader = $_SERVER['HTTP_X_API_TOKEN'] ?? '';
  if ($apiHeader !== '' && hash_equals($token, $apiHeader)) {
    return 'api';
  }

  // Also allow passing API token via Authorization: Bearer <token>
  // (only if the token doesn't look like a JWT — no dots)
  $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
  if (preg_match('/^Bearer\s+(.+)$/i', $authHeader, $m)) {
    $bearer = $m[1];
    // JWT has dots — skip; plain token — check
    if (strpos($bearer, '.') === false && hash_equals($token, $bearer)) {
      return 'api';
    }
  }

  return null;
}

/**
 * Resolve authenticated user: JWT login OR API token.
 * Returns login string or null (unauthenticated).
 */
function resolve_user(array $config): ?string {
  if (!$config['auth']['enabled']) return 'public';
  $jwtUser = get_auth_user($config);
  if ($jwtUser !== null) return $jwtUser;
  return check_api_token($config);
}

// ── Challenge storage (file-based, CGI-safe) ──────────────────────

function store_challenge(string $token, string $realm, string $challenge, string $routerCookie = '', string $authUrl = ''): void {
  $challenges = [];
  if (file_exists(CHALLENGES_FILE)) {
    $challenges = json_decode(file_get_contents(CHALLENGES_FILE), true) ?? [];
  }
  // Cleanup expired
  $now = time();
  foreach ($challenges as $key => $val) {
    if ($now - ($val['ts'] ?? 0) > CHALLENGE_TTL) {
      unset($challenges[$key]);
    }
  }
  $challenges[$token] = ['realm' => $realm, 'challenge' => $challenge, 'cookie' => $routerCookie, 'authUrl' => $authUrl, 'ts' => $now];

  $dir = dirname(CHALLENGES_FILE);
  if (!is_dir($dir)) mkdir($dir, 0755, true);
  file_put_contents(CHALLENGES_FILE, json_encode($challenges), LOCK_EX);
}

function consume_challenge(string $token): ?array {
  if (!file_exists(CHALLENGES_FILE)) return null;
  $challenges = json_decode(file_get_contents(CHALLENGES_FILE), true) ?? [];
  if (!isset($challenges[$token])) return null;

  $entry = $challenges[$token];

  // Expired?
  if (time() - ($entry['ts'] ?? 0) > CHALLENGE_TTL) {
    unset($challenges[$token]);
    file_put_contents(CHALLENGES_FILE, json_encode($challenges), LOCK_EX);
    return null;
  }

  // Delete after one use
  unset($challenges[$token]);
  file_put_contents(CHALLENGES_FILE, json_encode($challenges), LOCK_EX);

  return $entry;
}

// ── Device helpers (ported from device-helpers.ts) ────────────────

function normalize_hosts(array $data): array {
  if (!isset($data['host'])) return [];
  $hosts = $data['host'];
  return is_array($hosts) ? (isset($hosts[0]) ? $hosts : [$hosts]) : [];
}

function compare_devices(array $a, array $b): int {
  if ($a['active'] !== $b['active']) return $a['active'] ? -1 : 1;
  return strcmp($a['name'] ?: $a['mac'], $b['name'] ?: $b['mac']);
}

function build_policy_set_payload(string $mac, string $policy): array {
  return [
    'ip' => [
      'hotspot' => [
        'host' => ['mac' => $mac, 'permit' => true, 'policy' => $policy],
      ],
    ],
    'system' => ['configuration' => ['save' => (object)[]]],
  ];
}

function build_policy_remove_payload(string $mac): array {
  return [
    'ip' => [
      'hotspot' => [
        'host' => ['mac' => $mac, 'policy' => ['no' => true]],
      ],
    ],
    'system' => ['configuration' => ['save' => (object)[]]],
  ];
}

function build_dns_profile_payload(string $mac, ?string $dnsProfile): array {
  $profile = $dnsProfile
    ? ['host' => $mac, 'profile' => $dnsProfile]
    : ['host' => $mac, 'no' => true];
  return [
    'dns-proxy' => [
      'filter' => [
        'assign' => [
          'host' => ['profile' => $profile],
        ],
      ],
    ],
  ];
}

function merge_devices(array $activeHosts, array $configHosts, array $policies): array {
  $configMap = [];
  foreach ($configHosts as $host) {
    if (!empty($host['mac'])) {
      $configMap[strtolower($host['mac'])] = $host;
    }
  }

  $deviceMap = [];
  $resolveLabel = function(string $policyId) use ($policies): string {
    foreach ($policies as $p) {
      if ($p['id'] === $policyId) return $p['label'];
    }
    return $policyId ?: ($policies[0]['label'] ?? '');
  };

  // Active devices
  foreach ($activeHosts as $host) {
    if (empty($host['mac'])) continue;
    $mac = strtolower($host['mac']);
    $config = $configMap[$mac] ?? [];
    $policy = $config['policy'] ?? '';
    $deviceMap[$mac] = [
      'mac'         => $mac,
      'name'        => $config['name'] ?? $host['name'] ?? $host['hostname'] ?? '',
      'ip'          => $host['ip'] ?? '',
      'hostname'    => $host['hostname'] ?? '',
      'active'      => ($host['active'] ?? true) !== false,
      'registered'  => ($config['registered'] ?? false) !== false || !empty($config),
      'policy'      => $policy,
      'policyLabel' => $resolveLabel($policy),
    ];
  }

  // Registered-but-offline
  foreach ($configHosts as $host) {
    if (empty($host['mac'])) continue;
    $mac = strtolower($host['mac']);
    if (isset($deviceMap[$mac])) continue;
    $policy = $host['policy'] ?? '';
    $deviceMap[$mac] = [
      'mac'         => $mac,
      'name'        => $host['name'] ?? $host['hostname'] ?? '',
      'ip'          => $host['ip'] ?? '',
      'hostname'    => $host['hostname'] ?? '',
      'active'      => false,
      'registered'  => true,
      'policy'      => $policy,
      'policyLabel' => $resolveLabel($policy),
    ];
  }

  $result = array_values($deviceMap);
  usort($result, 'compare_devices');
  return $result;
}

function normalize_ip(string $ip): string {
  // Strip IPv4-mapped IPv6 prefix
  if (preg_match('/^::ffff:(\d+\.\d+\.\d+\.\d+)$/', $ip, $m)) {
    return $m[1];
  }
  // Strip scope ID
  $pos = strpos($ip, '%');
  if ($pos !== false) return substr($ip, 0, $pos);
  return $ip;
}

function find_device_mac_by_ip(string $rciUrl, string $clientIp, array $policies): ?string {
  $activeHosts = normalize_hosts(rci_get($rciUrl, '/rci/show/ip/hotspot'));
  $configHosts = normalize_hosts(rci_get($rciUrl, '/rci/ip/hotspot'));
  $devices = merge_devices($activeHosts, $configHosts, $policies);
  $normalized = normalize_ip($clientIp);
  if (!$normalized) return null;

  foreach ($devices as $d) {
    if (normalize_ip($d['ip']) === $normalized) {
      return $d['mac'];
    }
  }
  return null;
}

// ── Policy validation (ported from config.ts) ─────────────────────

function validate_policies(array $input): array {
  if (empty($input)) {
    throw new InvalidArgumentException('Policies must be a non-empty array');
  }

  $ids = [];
  foreach ($input as $i => $row) {
    if (!is_array($row)) {
      throw new InvalidArgumentException('Row ' . ($i + 1) . ': expected an object');
    }

    $id = strval($row['id'] ?? '');
    // First row must have empty id
    if ($i === 0 && $id !== '') {
      throw new InvalidArgumentException('Row 1: the first policy must have id="" (no-policy option)');
    }

    if (isset($ids[$id])) {
      throw new InvalidArgumentException('Duplicate policy id "' . $id . '" at rows ' . $ids[$id] . ' and ' . ($i + 1));
    }
    $ids[$id] = $i + 1;

    $symbol = strval($row['symbol'] ?? '');
    if (trim($symbol) === '') {
      throw new InvalidArgumentException('Row ' . ($i + 1) . ': "symbol" is required');
    }

    $color = strval($row['color'] ?? '');
    if (!preg_match('/^#[0-9a-fA-F]{6}$/', $color)) {
      throw new InvalidArgumentException('Row ' . ($i + 1) . ': "color" must be a hex color (e.g. #ffffff)');
    }

    $label = strval($row['label'] ?? '');
    if (trim($label) === '') {
      throw new InvalidArgumentException('Row ' . ($i + 1) . ': "label" is required');
    }

    if (isset($row['dnsProfile']) && $row['dnsProfile'] !== '' && $row['dnsProfile'] !== null) {
      // dnsProfile must be a non-empty string if present
      if (!is_string($row['dnsProfile']) || trim($row['dnsProfile']) === '') {
        throw new InvalidArgumentException('Row ' . ($i + 1) . ': "dnsProfile" must be a non-empty string if provided');
      }
    }
  }

  return $input;
}

// ── Load policies from file ───────────────────────────────────────

function load_policies(string $filePath): array {
  if (file_exists($filePath)) {
    $raw = file_get_contents($filePath);
    $parsed = json_decode($raw, true);
    if (is_array($parsed)) {
      return $parsed;
    }
  }

  // Create default
  $defaults = [
    ['id' => '', 'symbol' => 'DEF', 'color' => '#ffffff', 'label' => 'Default'],
  ];
  $dir = dirname($filePath);
  if (!is_dir($dir)) mkdir($dir, 0755, true);
  file_put_contents($filePath, json_encode($defaults, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
  return $defaults;
}

// ── Response helpers ──────────────────────────────────────────────

function json_response(mixed $data, int $status = 200): void {
  http_response_code($status);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode($data, JSON_UNESCAPED_UNICODE);
  exit;
}

function json_error(string $message, int $status = 400): void {
  json_response(['error' => $message], $status);
}

// ── Router + Handlers ─────────────────────────────────────────────

function handle_request(): void {
  $config = load_config();

  // Set timezone from system
  $tz = @trim(@exec('cat /etc/TZ 2>/dev/null'));
  if ($tz) @date_default_timezone_set($tz);

  $method = $_SERVER['REQUEST_METHOD'];
  $uri    = $_SERVER['REQUEST_URI'];

  // Strip query string
  $path = parse_url($uri, PHP_URL_PATH);

  $rciUrl      = $config['router']['rci_url'];
  $authEnabled = !empty($config['auth']['enabled']);
  $policiesFile = $config['app']['policies_file'] ?: DEFAULT_POLICIES_FILE;
  $GLOBALS['logLevel'] = parse_log_level($config['app']['log_level'] ?? 'warn');
  $GLOBALS['logFile']  = $config['app']['log_file'] ?? '';

  // Detect router LAN IP for auth endpoint (127.0.0.1 gives 403 on Keenetic)
  $lanIp = @trim(@exec("ip -4 addr show br0 2>/dev/null | grep inet | awk '{print \$2}' | cut -d/ -f1"));
  if (!$lanIp) $lanIp = parse_url($rciUrl, PHP_URL_HOST) ?: '127.0.0.1';
  log_msg(L_DEBUG, 'Auth: LAN IP detected', ['lanIp' => $lanIp, 'rciUrl' => $rciUrl]);

  $user = $authEnabled ? resolve_user($config) : 'public';

  $clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
  log_msg(L_DEBUG, "$method $path", [], $clientIp);

  // If X-API-Token header is present but didn't match → explicit 401
  $hasApiHeader = ($_SERVER['HTTP_X_API_TOKEN'] ?? '') !== '';
  if ($hasApiHeader && $user === null) {
    log_msg(L_WARN, 'Invalid API token attempted', [], $clientIp);
    json_error('Invalid API token', 401);
  }

  // ── GET /api/config ─────────────────────────────────
  if ($method === 'GET' && $path === '/api/config') {
    json_response(['authRequired' => $authEnabled]);
  }

  // ── GET /api/myip ───────────────────────────────────
  if ($method === 'GET' && $path === '/api/myip') {
    $ip = $_SERVER['REMOTE_ADDR'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '127.0.0.1';
    json_response(['ip' => $ip]);
  }

  // ── GET /api/health ─────────────────────────────────
  if ($method === 'GET' && $path === '/api/health') {
    try {
      rci_get($rciUrl, '/rci/show/version');
      json_response(['status' => 'ok', 'router' => parse_url($rciUrl, PHP_URL_HOST) ?: '127.0.0.1']);
    } catch (RuntimeException $e) {
      json_response(['status' => 'unreachable', 'router' => parse_url($rciUrl, PHP_URL_HOST) ?: '127.0.0.1'], 503);
    }
  }

  // ── GET /api/policies ───────────────────────────────
  if ($method === 'GET' && $path === '/api/policies') {
    json_response(load_policies($policiesFile));
  }

  // ── PUT /api/policies (auth required) ───────────────
  if ($method === 'PUT' && $path === '/api/policies') {
    if ($authEnabled && !$user) {
      json_error('Authentication required', 401);
    }
    $body = json_decode(file_get_contents('php://input'), true);
    if (!is_array($body)) {
      json_error('Invalid JSON body');
    }
    try {
      $validated = validate_policies($body);
      $dir = dirname($policiesFile);
      if (!is_dir($dir)) mkdir($dir, 0755, true);
      $tmp = $policiesFile . '.tmp';
      file_put_contents($tmp, json_encode($validated, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
      rename($tmp, $policiesFile);
      json_response(['success' => true, 'policies' => $validated]);
    } catch (InvalidArgumentException $e) {
      json_error($e->getMessage(), 400);
    }
  }

  // ── GET /api/router/policies (auth required) ────────
  if ($method === 'GET' && $path === '/api/router/policies') {
    if ($authEnabled && !$user) json_error('Authentication required', 401);
    try {
      json_response(rci_get($rciUrl, '/rci/show/ip/policy'));
    } catch (RuntimeException $e) {
      json_error('Failed to fetch router policies: ' . $e->getMessage(), 502);
    }
  }

  // ── GET /api/router/dns-profiles (auth required) ───
  if ($method === 'GET' && $path === '/api/router/dns-profiles') {
    if ($authEnabled && !$user) json_error('Authentication required', 401);
    try {
      json_response(rci_get($rciUrl, '/rci/show/dns-proxy/filter/profiles'));
    } catch (RuntimeException $e) {
      json_error('Failed to fetch DNS profiles: ' . $e->getMessage(), 502);
    }
  }

  // ── GET /api/session/challenge — proxy to router /auth ──
  if ($method === 'GET' && $path === '/api/session/challenge') {
    // Detect web UI port dynamically via RCI
    $host = $lanIp;
    $webPort = '80';
    $ch = curl_init($rciUrl . '/rci/ip/http/port');
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_TIMEOUT        => RCI_TIMEOUT,
      CURLOPT_CONNECTTIMEOUT => RCI_TIMEOUT,
      CURLOPT_NOSIGNAL       => 1,
    ]);
    $portBody = curl_exec($ch);
    $portHttp = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($portHttp >= 200 && $portHttp < 300) {
      $detected = trim($portBody, " \t\n\r\0\x0B\"");
      if (is_numeric($detected)) {
        $webPort = $detected;
      }
    }
    $authUrl = "http://{$host}:{$webPort}/auth";

    $headers = [];
    $ch = curl_init($authUrl);
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_TIMEOUT        => RCI_TIMEOUT,
      CURLOPT_CONNECTTIMEOUT => RCI_TIMEOUT,
      CURLOPT_NOSIGNAL       => 1,
      CURLOPT_HEADERFUNCTION => function($ch, $header) use (&$headers) {
        $len = strlen($header);
        if (stripos($header, 'X-NDM-Realm:') === 0) {
          $headers['realm'] = trim(substr($header, 12));
        } elseif (stripos($header, 'X-NDM-Challenge:') === 0) {
          $headers['challenge'] = trim(substr($header, 16));
        } elseif (stripos($header, 'Set-Cookie:') === 0) {
          $headers['cookie'] = trim(substr($header, 11));
        }
        return $len;
      },
    ]);
    $body = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErrno = curl_errno($ch);
    $curlError = curl_error($ch);
    curl_close($ch);

    log_msg(L_DEBUG, 'Auth: challenge response', [
      'authUrl' => $authUrl,
      'httpCode' => $httpCode,
      'curlErrno' => $curlErrno,
      'curlError' => $curlError,
      'realm' => $headers['realm'] ?? '(missing)',
      'challenge' => $headers['challenge'] ?? '(missing)',
      'cookie' => isset($headers['cookie']) ? substr($headers['cookie'], 0, 30) . '...' : '(none)',
    ]);

    if (empty($headers['realm']) || empty($headers['challenge'])) {
      json_error('Failed to get challenge from router', 502);
    }

    $token = bin2hex(random_bytes(32));
    store_challenge($token, $headers['realm'], $headers['challenge'], $headers['cookie'] ?? '', $authUrl);
    json_response(['realm' => $headers['realm'], 'challenge' => $headers['challenge'], 'token' => $token]);
  }

  // ── POST /api/session — verify hash via router /auth ──
  if ($method === 'POST' && $path === '/api/session') {
    $body = json_decode(file_get_contents('php://input'), true);
    $login = strval($body['login'] ?? '');
    $hash  = strval($body['hash'] ?? '');
    $token = strval($body['token'] ?? '');

    $stored = consume_challenge($token);
    if (!$stored) {
      json_error('login, hash, and a valid challenge token are required', 400);
    }

    // Forward hash to router for verification (use authUrl stored from challenge step)
    $authUrl = $stored['authUrl'] ?? 'http://' . $lanIp . '/auth';
    $payload = json_encode(['login' => $login, 'password' => $hash]);
    $ch = curl_init($authUrl);
    $reqHeaders = ['Content-Type: application/json'];
    if (!empty($stored['cookie'])) {
      $reqHeaders[] = 'Cookie: ' . $stored['cookie'];
    }
    curl_setopt_array($ch, [
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_POST           => true,
      CURLOPT_POSTFIELDS     => $payload,
      CURLOPT_HTTPHEADER     => $reqHeaders,
      CURLOPT_TIMEOUT        => RCI_TIMEOUT,
      CURLOPT_CONNECTTIMEOUT => RCI_TIMEOUT,
      CURLOPT_NOSIGNAL       => 1,
    ]);
    curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode !== 200) {
      log_msg(L_WARN, 'Login failed', [], $clientIp);
      json_error('Invalid credentials', 401);
    }

    log_msg(L_INFO, 'Login successful', ['user' => $login], $clientIp);
    $jwt = issue_jwt($login, get_jwt_secret($config));
    json_response(['token' => $jwt]);
  }

  // ── GET /api/devices ────────────────────────────────
  if ($method === 'GET' && $path === '/api/devices') {
    $policies = load_policies($policiesFile);
    try {
      $activeHosts = normalize_hosts(rci_get($rciUrl, '/rci/show/ip/hotspot'));
      $configHosts = normalize_hosts(rci_get($rciUrl, '/rci/ip/hotspot'));
    } catch (RuntimeException $e) {
      log_msg(L_ERROR, 'Failed to fetch devices from router', [], $clientIp);
      json_error('Failed to fetch devices from router', 502);
    }

    $allDevices = merge_devices($activeHosts, $configHosts, $policies);

    // Auth filter: if auth enabled and no user, return only matching IP
    if ($authEnabled && !$user) {
      $clientIp = normalize_ip($_SERVER['REMOTE_ADDR'] ?? '');
      $filtered = array_values(array_filter($allDevices, function($d) use ($clientIp) {
        return normalize_ip($d['ip']) === $clientIp;
      }));
      json_response($filtered);
    }

    json_response($allDevices);
  }

  // ── POST /api/devices/:mac/policy ───────────────────
  if ($method === 'POST' && preg_match('#^/api/devices/([^/]+)/policy$#', $path, $m)) {
    $mac = strtolower(urldecode($m[1]));

    if (!preg_match('/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/', $mac)) {
      json_error('Invalid MAC address format', 400);
    }

    $body = json_decode(file_get_contents('php://input'), true);
    $policy = strval($body['policy'] ?? '');

    $policies = load_policies($policiesFile);
    $valid = false;
    foreach ($policies as $p) {
      if ($p['id'] === $policy) { $valid = true; break; }
    }
    if (!$valid) {
      $available = array_map(function($p) { return '"' . $p['id'] . '"'; }, $policies);
      json_error('Unknown policy "' . $policy . '". Available: ' . implode(', ', $available), 400);
    }

    // Auth check
    if ($authEnabled && !$user) {
      $myMac = find_device_mac_by_ip($rciUrl, $_SERVER['REMOTE_ADDR'] ?? '', $policies);
      if (!$myMac || $myMac !== $mac) {
        json_error('Authentication required — you can only change policy for your own device', 403);
      }
    }

    try {
      $payload = $policy === ''
        ? build_policy_remove_payload($mac)
        : build_policy_set_payload($mac, $policy);

      // Add DNS profile payload if configured
      $dnsProfile = null;
      foreach ($policies as $p) {
        if ($p['id'] === $policy && !empty($p['dnsProfile'])) {
          $dnsProfile = $p['dnsProfile'];
          break;
        }
      }
      $dnsPayload = build_dns_profile_payload($mac, $dnsProfile);

      rci_post($rciUrl, '/rci/', array_merge($payload, $dnsPayload));

      // Verify
      $verified = false;
      try {
        $configHosts = normalize_hosts(rci_get($rciUrl, '/rci/ip/hotspot'));
        foreach ($configHosts as $host) {
          if (strtolower($host['mac'] ?? '') === $mac) {
            $verified = ($host['policy'] ?? '') === $policy;
            break;
          }
        }
      } catch (RuntimeException $e) {
        // verification failed, don't throw
      }

      $policyLabel = '';
      foreach ($policies as $p) {
        if ($p['id'] === $policy) { $policyLabel = $p['label']; break; }
      }

	      $v = $verified ? '' : ' (verification failed)';
	      log_msg(L_INFO, "Policy \"$policyLabel\" set for $mac from $clientIp$v");
      json_response(['success' => true, 'verified' => $verified, 'policy' => $policy, 'policyLabel' => $policyLabel]);
    } catch (RuntimeException $e) {
	      log_msg(L_ERROR, "Failed to set policy for $mac", [], $clientIp);
      json_error('Failed to set policy for ' . $mac, 500);
    }
  }

  // ── POST /api/policy (set by client IP) ─────────────
  if ($method === 'POST' && $path === '/api/policy') {
    $body = json_decode(file_get_contents('php://input'), true);
    $policy = strval($body['policy'] ?? '');

    $policies = load_policies($policiesFile);
    $valid = false;
    foreach ($policies as $p) {
      if ($p['id'] === $policy) { $valid = true; break; }
    }
    if (!$valid) {
      $available = array_map(function($p) { return '"' . $p['id'] . '"'; }, $policies);
      json_error('Unknown policy "' . $policy . '". Available: ' . implode(', ', $available), 400);
    }

    $mac = find_device_mac_by_ip($rciUrl, $_SERVER['REMOTE_ADDR'] ?? '', $policies);
    if (!$mac) {
      json_error('No device found for your IP address', 404);
    }

    try {
      $payload = $policy === ''
        ? build_policy_remove_payload($mac)
        : build_policy_set_payload($mac, $policy);
      $dnsProfile = null;
      foreach ($policies as $p) {
        if ($p['id'] === $policy && !empty($p['dnsProfile'])) {
          $dnsProfile = $p['dnsProfile'];
          break;
        }
      }
      $dnsPayload = build_dns_profile_payload($mac, $dnsProfile);
      rci_post($rciUrl, '/rci/', array_merge($payload, $dnsPayload));

      $policyLabel = '';
      foreach ($policies as $p) {
        if ($p['id'] === $policy) { $policyLabel = $p['label']; break; }
      }

      log_msg(L_INFO, "Policy \"$policyLabel\" set for $mac");
      json_response(['success' => true, 'verified' => true, 'policy' => $policy, 'policyLabel' => $policyLabel]);
    } catch (RuntimeException $e) {
	      log_msg(L_ERROR, "Failed to set policy for $mac", [], $clientIp);
      json_error('Failed to set policy for ' . $mac, 500);
    }
  }

  // ── 404 fallback ────────────────────────────────────
  json_error('Not Found', 404);
}

// ── Entry point ───────────────────────────────────────────────────

try {
  handle_request();
} catch (RuntimeException $e) {
  json_error($e->getMessage(), 500);
} catch (Throwable $e) {
  http_response_code(500);
  header('Content-Type: application/json; charset=utf-8');
  echo json_encode(['error' => 'Internal server error']);
  error_log('keenetic-policy-ui error: ' . $e->getMessage());
}
