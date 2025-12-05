<?php

use CodeIgniter\Database\BaseConnection;
use CodeIgniter\HTTP\ResponseInterface;
use Config\Database;
use Config\Services;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
/**
 * Ambil tenant id aktif dari session (fallback 1)
 */
if (!function_exists('current_tenant_id')) {
    function current_tenant_id(): int
    {
        $tid = (int) (session()->get('tenant_id') ?? 0);
        return $tid > 0 ? $tid : 1;
    }
}

/* ===============================
 * PCare (JKN Dev)
 * =============================== */

if (!function_exists('pcare_get_config')) {
    /**
     * Ambil konfigurasi PCare per tenant
     */
    function pcare_get_config(?int $tenantId = null): ?array
    {
        $tenantId = $tenantId ?: current_tenant_id();
        $db = db_connect();
        return $db->table('bpjs_pcare_config')
            ->where('id_tenant', $tenantId)
            ->where('is_active', 1)
            ->orderBy('id','DESC')
            ->get()->getRowArray();
    }
}

if (!function_exists('pcare_build_headers')) {
    /**
     * Build header PCare: X-cons-id, X-Timestamp, X-Signature, user_key
     * Signature = base64( HMACSHA256( cons_id & timestamp, secret_key ) )
     * Timestamp = epoch UTC (detik)
     */
function pcare_build_headers(array $cfg): array
{
    $consId    = trim($cfg['cons_id']);
    $secretKey = trim($cfg['secret_key']);
    $userKey   = trim($cfg['user_key']);
    $username  = trim($cfg['username']);    // dari tabel
    $password  = trim($cfg['password']);    // dari tabel
    $kdApp     = trim($cfg['kd_app'] ?? '095');

    $timestamp = (string) time();
    $signature = base64_encode(hash_hmac('sha256', $consId.'&'.$timestamp, $secretKey, true));

    $xAuth = base64_encode($username.':'.$password.':'.$kdApp);

    return [
        'Accept'          => 'application/json; charset=utf-8',
        'Content-Type'    => 'application/json; charset=utf-8',
        'X-Cons-Id'       => $consId,
        'X-Timestamp'     => $timestamp,
        'X-Signature'     => $signature,
        'X-Authorization' => "Basic ".$xAuth,   // ← TIDAK diawali “Basic ”
        'user_key'        => $userKey, // snake-case sesuai dok
    ];
}



}
if (!function_exists('pcare_pick_message')) {
    /**
     * Ambil pesan human-readable dari berbagai bentuk response PCare.
     * Mengembalikan string atau null.
     */
    function pcare_pick_message($data): ?string
    {
        if (is_string($data)) {
            // kadang HTML error / plain string dari server
            return trim($data);
        }

        if (!is_array($data)) {
            return null;
        }

        // Bentuk normal: { response: { field, message }, metaData: { message, code } }
        if (isset($data['response']['message']) && is_scalar($data['response']['message'])) {
            return (string) $data['response']['message'];
        }

        if (isset($data['metaData']['message']) && is_scalar($data['metaData']['message'])) {
            return (string) $data['metaData']['message'];
        }

        // Bentuk error umum lain
        if (isset($data['error']) && is_scalar($data['error'])) {
            return (string) $data['error'];
        }

        // Fallback: string-kan saja
        return json_encode($data);
    }
}

if (!function_exists('pcare_post_plain')) {
    /**
     * Kirim POST ke PCare dengan Content-Type: text/plain dan body JSON string.
     * Dipakai utk endpoint tertentu (mis: /kelompok/kegiatan, /kelompok/peserta).
     */
   function pcare_post_plain(string $path, array $payload, ?int $tenantId = null): array
{
    $cfg = pcare_get_config($tenantId);
    if (!$cfg) {
        return ['success'=>false,'status'=>0,'data'=>null,'error'=>'PCare config not found'];
    }

    $client  = \Config\Services::curlrequest(['http_errors'=>false,'timeout'=>40]);

    $url     = rtrim($cfg['base_url'], '/') . '/' . ltrim($path, '/');
    $headers = pcare_build_headers($cfg);     // <- berisi X-Timestamp yg kita butuhkan
    $xTs     = $headers['X-Timestamp'] ?? (string) time();

    // text/plain body
    $headers['Content-Type'] = 'text/plain';
    $body = json_encode($payload, JSON_UNESCAPED_UNICODE);
 $json = json_encode($payload, JSON_PRETTY_PRINT);
// echo $json;
    $res  = $client->post($url, ['headers'=>$headers, 'body'=>$body]);
    $raw  = (string) $res->getBody();
    $json = json_decode($raw, true);
// echo json_encode($res, JSON_PRETTY_PRINT);
    // ====== AUTO-DECRYPT (kalau memungkinkan) ======
    $decrypted = null;
    if (is_array($json) && isset($json['metaData']['code']) && isset($json['response']) && is_string($json['response']) && $json['response'] !== '') {
        $dec = pcare_try_decrypt_response($cfg, $json['response'], $xTs);
        if ($dec) {
            $decJson = json_decode($dec, true);
            $json['response'] = $decJson ?: $dec; // ganti response jadi array (kalau JSON) atau raw string
            $decrypted = $json;
        }
    } else {
        // kalau bukan bentuk standar, cek apakah RAW terlihat seperti base64 cipher → coba decrypt langsung
        if (is_string($raw) && preg_match('~^[A-Za-z0-9+/=]+$~', trim($raw))) {
            $dec = pcare_try_decrypt_response($cfg, trim($raw), $xTs);
            if ($dec) {
                $decJson  = json_decode($dec, true);
                $decrypted = $decJson ?: ['response_raw' => $dec];
            }
        }
    }


    // siapkan keluaran
    $ok     = $res->getStatusCode() >= 200 && $res->getStatusCode() < 300;
    $out    = [
        'success'     => $ok,
        'status'      => $res->getStatusCode(),
        'data'        => $decrypted ?? ($json ?? ['raw'=>$raw]),
        'raw'         => $raw,
        'x_timestamp' => $xTs,
        'error'       => $ok ? null : (pcare_pick_message($decrypted ?? $json ?? $raw) ?: 'HTTP '.$res->getStatusCode()),
    ];

    return $out;
}

}

if (!function_exists('pcare_pick_messages_from_raw')) {
    /**
     * Parse raw string JSON dari PCare dan pulangkan ringkasan pesan.
     * Return:
     * [
     *   'meta'   => 'PRECONDITION_FAILED',
     *   'fields' => ['clubId' => 'Tidak sesuai dengan referensi sistem.'],
     *   'joined' => 'clubId: Tidak sesuai dengan referensi sistem.'
     * ]
     */
    function pcare_pick_messages_from_raw($raw): array
    {
        $out = ['meta' => null, 'fields' => [], 'joined' => null];

        if (!is_string($raw) || $raw === '') {
            return $out;
        }

        $json = json_decode($raw, true);
        if (!is_array($json)) {
            // raw bukan JSON; kirim apa adanya
            $out['joined'] = trim($raw);
            return $out;
        }

        // meta
        if (isset($json['metaData']['message'])) {
            $out['meta'] = (string) $json['metaData']['message'];
        }

        // response bisa array of objects {field, message} atau object {field,message}
        if (isset($json['response'])) {
            if (is_array($json['response'])) {
                foreach ($json['response'] as $row) {
                    if (is_array($row) && isset($row['field'], $row['message'])) {
                        $out['fields'][(string)$row['field']] = (string)$row['message'];
                    }
                }
            } elseif (is_array($json['response']) && isset($json['response']['field'], $json['response']['message'])) {
                $out['fields'][(string)$json['response']['field']] = (string)$json['response']['message'];
            }
        }

        if (!empty($out['fields'])) {
            $pairs = [];
            foreach ($out['fields'] as $f => $m) {
                $pairs[] = "{$f}: {$m}";
            }
            $out['joined'] = implode('; ', $pairs);
        } else {
            // fallback, coba meta
            $out['joined'] = $out['meta'] ?: json_encode($json);
        }

        return $out;
    }
}

if (!function_exists('pcare_request')) {
    function pcare_request(string $method, string $path, $payload = null, ?int $tenantId = null): array
    {
        $cfg = pcare_get_config($tenantId);
        if (!$cfg) {
            return ['success'=>false,'status'=>0,'data'=>null,'error'=>'PCare config not found'];
        }

        $client  = \Config\Services::curlrequest(['http_errors'=>false,'timeout'=>30]);
        $url     = rtrim($cfg['base_url'], '/') . '/' . ltrim($path, '/');
//   echo $url;
//   print_r($payload);
        $headers = pcare_build_headers($cfg);

        $options = ['headers' => $headers];
        if (in_array(strtoupper($method), ['POST','PUT','PATCH','DELETE'], true)) {
            $options['json'] = $payload;
        }

        $res  = $client->request(strtoupper($method), $url, $options);
        $body = (string) $res->getBody();
        $json = json_decode($body, true);

        // ==== AUTO DECRYPT ====
        // Pola respons: {"response":"<cipher>","metaData":{"code":200,...}}
        if (is_array($json)
            && isset($json['metaData']['code'])
            && (int)$json['metaData']['code'] === 200
            && isset($json['response'])
            && is_string($json['response'])
            && $json['response'] !== ''
        ) {
            $dec = pcare_try_decrypt_response($cfg, $json['response'], $headers['X-Timestamp']);
            if ($dec) {
                $decodedPayload = json_decode($dec, true);
                // Jika hasil decrypt JSON valid, gantikan 'response' jadi array;
                // kalau bukan JSON, letakkan sebagai 'response_raw'
                if (is_array($decodedPayload)) {
                    $json['response'] = $decodedPayload;
                } else {
                    $json['response_raw'] = $dec;
                }
            }
        }

        return [
            'success' => $res->getStatusCode() >= 200 && $res->getStatusCode() < 300,
            'status'  => $res->getStatusCode(),
            'data'    => $json ?? $body,
            'error'   => $res->getStatusCode() >= 400
                        ? (($json['metaData']['message'] ?? $body) ?: 'HTTP '.$res->getStatusCode())
                        : null,
        ];
    }
}

if (!function_exists('pcare_try_decrypt_response')) {
    /**
     * Decrypt + decompress response PCare / VClaim.
     * Key = cons_id . secret_key . timestamp
     */
    function pcare_try_decrypt_response(array $cfg, string $cipher, string $timestamp): ?string
    {
        $keyMaterial = $cfg['cons_id'] . $cfg['secret_key'] . $timestamp;
        $keyHash = hex2bin(hash('sha256', $keyMaterial));
        $iv      = substr($keyHash, 0, 16);

        $plain = openssl_decrypt(
            base64_decode($cipher),
            'AES-256-CBC',
            $keyHash,
            OPENSSL_RAW_DATA,
            $iv
        );
        if ($plain === false || $plain === null) {
            return null;
        }

        // decompress jika library tersedia; jika gagal, kembalikan apa adanya
        if (class_exists('\LZCompressor\LZString')) {
            $decomp = \LZCompressor\LZString::decompressFromEncodedURIComponent($plain);
            return $decomp ?: $plain;
        }
        return $plain;
    }
}

if (!function_exists('pcare_get')) {
    function pcare_get(string $path, ?int $tenantId = null): array {  return pcare_request('GET', $path, null, $tenantId); }
}
if (!function_exists('pcare_post')) {
    function pcare_post(string $path, $payload, ?int $tenantId = null): array { return pcare_request('POST', $path, $payload, $tenantId); }
}
if (!function_exists('pcare_put')) {
    function pcare_put(string $path, $payload, ?int $tenantId = null): array { return pcare_request('PUT', $path, $payload, $tenantId); }
}
if (!function_exists('pcare_delete')) {
    function pcare_delete(string $path, $payload = null, ?int $tenantId = null): array { return pcare_request('DELETE', $path, $payload, $tenantId); }
}

if (!function_exists('icare_get_base_url')) {
    /**
     * Ambil base URL iCare dari config PCare (field url_icare).
     */
    function icare_get_base_url(?int $tenantId = null): ?string
    {
        $cfg = pcare_get_config($tenantId);
        if (!$cfg) {
            return null;
        }

        if (!empty($cfg['url_icare'])) {
            return rtrim($cfg['url_icare'], '/');
        }

        // fallback kalau url_icare kosong → pakai base_url
        if (!empty($cfg['base_url'])) {
            return rtrim($cfg['base_url'], '/');
        }

        return null;
    }
}

if (!function_exists('icare_post')) {
    /**
     * Kirim POST ke iCare
     *
     * @param string     $path    contoh: "api/pcare/validate"
     * @param array|mixed $payload body JSON
     * @param int|null   $tenantId
     *
     * return array {success,status,data,error}
     */
    function icare_post(string $path, $payload, ?int $tenantId = null): array
    {
        $cfg = pcare_get_config($tenantId);
        if (!$cfg) {
            return [
                'success' => false,
                'status'  => 0,
                'data'    => null,
                'error'   => 'iCare/PCare config not found',
            ];
        }

        $baseUrl = icare_get_base_url($tenantId);
        if (!$baseUrl) {
            return [
                'success' => false,
                'status'  => 0,
                'data'    => null,
                'error'   => 'iCare base_url (url_icare) tidak ditemukan',
            ];
        }

        // Service Name iCare (kalau ada), misal di .env:
        // BPJS_ICARE_SERVICE_NAME=icare
        $svcName = env('BPJS_ICARE_SERVICE_NAME', 'icare');

        $url     = $baseUrl . '/' . trim($svcName, '/') . '/' . ltrim($path, '/');
        $client  = \Config\Services::curlrequest(['http_errors' => false, 'timeout' => 30]);

        // header & signature sama dengan PCare
        $headers = pcare_build_headers($cfg);
        $options = [
            'headers' => $headers,
            'json'    => $payload,
        ];

        $res  = $client->post($url, $options);
        $code = $res->getStatusCode();
        $body = (string) $res->getBody();
        $json = json_decode($body, true);

        // ==== AUTO DECRYPT (sama pola PCare) ====
        if (is_array($json)
            && isset($json['metaData']['code'])
            && isset($json['response'])
            && is_string($json['response'])
            && $json['response'] !== ''
        ) {
            $ts  = $headers['X-Timestamp'] ?? (string) time();
            $dec = pcare_try_decrypt_response($cfg, $json['response'], $ts);
            if ($dec) {
                $decodedPayload = json_decode($dec, true);
                if (is_array($decodedPayload)) {
                    $json['response'] = $decodedPayload;
                } else {
                    $json['response_raw'] = $dec;
                }
            }
        }

        $ok = $code >= 200 && $code < 300;

        return [
            'success' => $ok,
            'status'  => $code,
            'data'    => $json ?? $body,
            'error'   => $ok
                        ? null
                        : (pcare_pick_message($json ?? $body) ?: 'HTTP '.$code),
        ];
    }
}

/**
 * Wrapper khusus dokumen:
 *   POST {BASE URL}/{Service Name}/api/pcare/validate
 *   Body: { "param": "<nilai>" }
 */
if (!function_exists('icare_validate_pcare')) {
    function icare_validate_pcare(string $param, ?int $tenantId = null): array
    {
        $payload = ['param' => $param];

        // path dari dokumen: api/pcare/validate
        return icare_post('api/pcare/validate', $payload, $tenantId);
    }
}
if (!function_exists('bpjs_antrol_get_config')) {
    function bpjs_antrol_get_config(?int $tenantId = null)
    {
        $db      = Database::connect();
        $builder = $db->table('bpjs_antrol_config')
                      ->where('is_active', 1);

        if ($tenantId !== null) {
            $builder->where('id_tenant', $tenantId);
        }

        return $builder->get()->getRow(); // stdClass|null
    }
}

/**
 * Generate header Antrol (x-cons-id, x-timestamp, x-signature, user_key)
 */
if (!function_exists('bpjs_antrol_build_headers')) {
    function bpjs_antrol_build_headers($config, ?string $timestamp = null): array
    {
        // timestamp epoch (detik)
        $tStamp    = $timestamp ?: (string) time();
        $consId    = $config->cons_id;
        $secretKey = env('BPJS_ANTROL_SECRET_KEY');  
        $userKey   = $config->user_key;

        // signature = base64_encode( HMAC-SHA256( consId&timestamp , secretKey ) )
        $sig = base64_encode(
            hash_hmac('sha256', $consId . '&' . $tStamp, $secretKey, true)
        );

        return [
            'x-cons-id'   => $consId,
            'x-timestamp' => $tStamp,
            'x-signature' => $sig,
            'user_key'    => $userKey,
            'Accept'      => 'application/json',
            'Content-Type'=> 'application/json',
        ];
    }
}

/**
 * Dekripsi response BPJS (field "response").
 * Di sini hanya AES-256-CBC. Kalau Antrol-mu pakai LZString, tambahkan decompress setelah decrypt.
 */
if (!function_exists('bpjs_antrol_decrypt')) {
    function bpjs_antrol_decrypt(string $cipherText, string $consId, string $secretKey, string $timestamp): string
    {
        // key = SHA256(consId + secretKey + timestamp)
        $key = hash('sha256', $consId . $secretKey . $timestamp, true);
        $iv  = substr($key, 0, 16);

        $decoded   = base64_decode($cipherText);
        $decrypted = openssl_decrypt(
            $decoded,
            'AES-256-CBC',
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );

        // Kalau dari BPJS masih terkompres LZ-string, di sini kamu tambah step dekompres:
        // $decrypted = lzstring_decompress($decrypted);

        return $decrypted ?: '';
    }
}

/**
 * Fungsi utama request ke Antrol (GET/POST/PUT/DELETE)
 */
if (!function_exists('bpjs_antrol_request')) {
    /**
     * @param string      $method   GET|POST|PUT|DELETE
     * @param string      $path     misal: "ref/poli/tanggal/2025-12-04"
     * @param array|null  $body     data json (POST/PUT/DELETE)
     * @param int|null    $tenantId
     *
     * @return array {status,http_code,raw,data,error?}
     */
    function bpjs_antrol_request(string $method, string $path, ?array $body = null, ?int $tenantId = null): array
    {
        $config = bpjs_antrol_get_config($tenantId);

        if (!$config) {
            return [
                'status'    => false,
                'http_code' => 0,
                'raw'       => '',
                'data'      => null,
                'error'     => 'Config Antrol tidak ditemukan / belum diaktifkan',
            ];
        }

        $serviceName = env('BPJS_ANTROL_SERVICE_NAME', 'antrean'); // misal: antreanRS
        $baseUrl     = rtrim($config->base_url, '/');
        $url         = $baseUrl . '/' . trim($serviceName, '/') . '/' . ltrim($path, '/');

        // timestamp dipakai juga untuk dekripsi
        $timestamp = (string) time();
        $headers   = bpjs_antrol_build_headers($config, $timestamp);

        /** @var \CodeIgniter\HTTP\CURLRequest $client */
        $client = Services::curlrequest([
            'timeout'     => 30,
            'http_errors' => false,
            'verify'      => false, // kalau production SSL valid, ubah ke true
        ]);

        $options = ['headers' => $headers];

        if (in_array(strtoupper($method), ['POST', 'PUT', 'DELETE']) && $body !== null) {
            $options['json'] = $body;
        }

        $response = $client->request($method, $url, $options);
        $code     = $response->getStatusCode();
        $rawBody  = $response->getBody();

        $data = json_decode($rawBody, true);

        // Jika ada field "response" terenkripsi → dekripsi
        $secretKey = env('BPJS_ANTROL_SECRET_KEY');
        if (is_array($data) && isset($data['response']) && is_string($data['response'])) {
            $plainJson = bpjs_antrol_decrypt($data['response'], $config->cons_id, $secretKey, $timestamp);

            $dec = json_decode($plainJson, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                $data['response_dec'] = $dec;
            } else {
                $data['response_dec_raw'] = $plainJson;
            }
        }

        return [
            'status'    => $code >= 200 && $code < 300,
            'http_code' => $code,
            'raw'       => $rawBody,
            'data'      => $data,
        ];
    }
}

/**
 * Shortcut GET / POST / PUT / DELETE
 */
if (!function_exists('bpjs_antrol_get')) {
    function bpjs_antrol_get(string $path, ?int $tenantId = null): array
    {
        return bpjs_antrol_request('GET', $path, null, $tenantId);
    }
}

if (!function_exists('bpjs_antrol_post')) {
    function bpjs_antrol_post(string $path, array $body, ?int $tenantId = null): array
    {
        return bpjs_antrol_request('POST', $path, $body, $tenantId);
    }
}

if (!function_exists('bpjs_antrol_put')) {
    function bpjs_antrol_put(string $path, array $body, ?int $tenantId = null): array
    {
        return bpjs_antrol_request('PUT', $path, $body, $tenantId);
    }
}

if (!function_exists('bpjs_antrol_delete')) {
    function bpjs_antrol_delete(string $path, ?array $body = null, ?int $tenantId = null): array
    {
        return bpjs_antrol_request('DELETE', $path, $body, $tenantId);
    }
}
/* ===============================
 * SATUSEHAT (DB Credentials)
 * =============================== */

// --- DIAGNOSTIK (shared global) ---
$GLOBALS['SATU_LAST_ERROR'] = null;

if (!function_exists('satu_set_last_error')) {
    function satu_set_last_error(?string $msg): void
    {
        $GLOBALS['SATU_LAST_ERROR'] = $msg;
        if ($msg) log_message('error', 'SATUSEHAT: '.$msg);
    }
}
if (!function_exists('satu_last_error')) {
    function satu_last_error(): ?string
    {
        return $GLOBALS['SATU_LAST_ERROR'] ?? null;
    }
}

if (!function_exists('satu_get_config')) {
    function satu_get_config(?int $tenantId = null): ?array
    {
        $tenantId = $tenantId ?: current_tenant_id();
        $db = db_connect();
        return $db->table('satu_sehat_config')
            ->where('id_tenant', $tenantId)
            ->where('is_active', 1)
            ->orderBy('id','DESC')
            ->get()->getRowArray();
    }
}

if (!function_exists('satu_get_client_credential')) {
    function satu_get_client_credential(int $tenantId): array
    {
        $cfg = satu_get_config($tenantId);
        if (!$cfg) {
            satu_set_last_error("config not found for tenant {$tenantId}");
            return ['', ''];
        }
        $cid = trim((string)($cfg['client_id'] ?? ''));
        $sec = trim((string)($cfg['client_secret'] ?? ''));
        if ($cid === '' || $sec === '') {
            satu_set_last_error("empty client_id/secret in DB for tenant {$tenantId}");
        }
        return [$cid, $sec];
    }
}

/**
 * Token flow: POST {auth_url}/accesstoken?grant_type=client_credentials
 * Body (x-www-form-urlencoded): client_id=...&client_secret=...
 * NOTE: body TIDAK mengandung grant_type.
 */
if (!function_exists('satu_get_token')) {
    function satu_get_token(array $cfg, int $tenantId): ?string
    {
        satu_set_last_error(null);

        // cache
        $cacheDir  = WRITEPATH . 'satusehat';
        if (!is_dir($cacheDir)) @mkdir($cacheDir, 0777, true);
        if (!is_writable($cacheDir)) {
            satu_set_last_error("cache dir not writable: {$cacheDir}");
        }
        $cacheFile = $cacheDir . '/satu_token_' . $tenantId . '.json';
        if (is_file($cacheFile)) {
            $raw = @file_get_contents($cacheFile);
            $obj = json_decode($raw, true);
            if ($obj && !empty($obj['access_token']) && time() < (int)($obj['expires_at'] ?? 0) - 60) {
                return $obj['access_token'];
            }
        }

        // credentials
        [$clientId, $clientSecret] = satu_get_client_credential($tenantId);
        if ($clientId === '' || $clientSecret === '') return null;

        // auth_url efektif: pastikan ada /accesstoken?grant_type=client_credentials
        $baseAuth = rtrim((string)($cfg['auth_url'] ?? ''), '/');
        if ($baseAuth === '') {
            satu_set_last_error("auth_url empty in config for tenant {$tenantId}");
            return null;
        }

        // Jika sudah mengandung 'accesstoken' dan grant_type di query, pakai apa adanya.
        $authUrl = $baseAuth;
        if (stripos($authUrl, 'accesstoken') === false) {
            $authUrl .= '/accesstoken';
        }
        // tambahkan grant_type di query bila belum ada
        $parsed = parse_url($authUrl);
        $qs     = [];
        if (!empty($parsed['query'])) parse_str($parsed['query'], $qs);
        if (empty($qs['grant_type'])) $qs['grant_type'] = 'client_credentials';
        $authUrl = rtrim(sprintf('%s://%s%s%s',
            $parsed['scheme'] ?? 'https',
            $parsed['host'] ?? '',
            isset($parsed['path']) ? $parsed['path'] : '',
            '?' . http_build_query($qs)
        ), '?');

        // HTTP client
        $client = \Config\Services::curlrequest([
            'http_errors'     => false,
            'timeout'         => 30,
            'allow_redirects' => true,
            // 'verify'       => false, // gunakan hanya di dev jika SSL bermasalah
        ]);

        // POST x-www-form-urlencoded: hanya client_id & client_secret
        try {
            $resp = $client->post($authUrl, [
                'headers'     => ['Content-Type' => 'application/x-www-form-urlencoded'],
                'form_params' => [
                    'client_id'     => $clientId,
                    'client_secret' => $clientSecret,
                    // JANGAN kirim grant_type di body!
                ],
            ]);
        } catch (\Throwable $e) {
            satu_set_last_error("HTTP exception: ".$e->getMessage());
            return null;
        }

        $status = $resp->getStatusCode();
        $body   = (string)$resp->getBody();

        // Server SATUSEHAT harusnya balas JSON dengan access_token
        $json   = json_decode($body, true);

        if ($status >= 200 && $status < 300 && is_array($json) && !empty($json['access_token'])) {
            $json['expires_at'] = time() + (int)($json['expires_in'] ?? 1800);
            @file_put_contents($cacheFile, json_encode($json));
            return $json['access_token'];
        }

        // Kalau 200 tapi bukan JSON (atau tidak ada access_token), log body untuk diagnosa
        satu_set_last_error("token failed; status={$status} body=" . substr($body, 0, 800));
        return null;
    }
}

if (!function_exists('satu_request')) {
    function satu_request(string $method, string $path, $payload = null, ?int $tenantId = null): array
    {
        $tenantId = $tenantId ?: current_tenant_id();
        $cfg = satu_get_config($tenantId);
        if (!$cfg) {
            return ['success'=>false,'status'=>0,'data'=>null,'error'=>'SatuSehat config not found'];
        }

        $token = satu_get_token($cfg, $tenantId);
        if (!$token) {
            $why = satu_last_error();
            return ['success'=>false,'status'=>0,'data'=>null,'error'=>'Unable to get SATUSEHAT token'.($why ? " — {$why}" : '')];
        }

        $client = \Config\Services::curlrequest(['http_errors'=>false,'timeout'=>40]);
        $url  = rtrim($cfg['base_url'], '/') . '/' . ltrim($path, '/');
        $opts = [
            'headers' => [
                'Authorization' => 'Bearer ' . $token,
                'Content-Type'  => 'application/fhir+json',
                'Accept'        => 'application/fhir+json',
            ],
        ];
        if (in_array(strtoupper($method), ['POST','PUT','PATCH','DELETE'], true)) {
            $opts['json'] = $payload;
        }

        $resp = $client->request(strtoupper($method), $url, $opts);
        $body = (string)$resp->getBody();
        $json = json_decode($body, true);

        return [
            'success' => $resp->getStatusCode() >= 200 && $resp->getStatusCode() < 300,
            'status'  => $resp->getStatusCode(),
            'data'    => $json ?? $body,
            'error'   => $resp->getStatusCode() >= 400 ? ($json['issue'][0]['diagnostics'] ?? $body) : null,
        ];
    }
}
// di helper
function satu_patient_by_nik(string $nik, ?int $tenantId = null): array
{
    $nik = trim($nik);
    if ($nik === '') {
        return ['success'=>false, 'status'=>400, 'message'=>'NIK wajib diisi'];
    }

    // system resmi SATUSEHAT
    $system = 'https://fhir.kemkes.go.id/id/nik';
    $q = rawurlencode($system . '|' . $nik);

    // pakai satu_get() yang sudah ada
    $res = satu_get("Patient?identifier={$q}", $tenantId);

    if (($res['success'] ?? false) && !empty($res['data']['entry'][0]['resource']['id'])) {
        $ihs = $res['data']['entry'][0]['resource']['id'];
        return [
            'success'    => true,
            'ihs_number' => $ihs,
            'resource'   => $res['data']['entry'][0]['resource'],
            'status'     => $res['status'] ?? 200
        ];
    }

    return [
        'success' => false,
        'status'  => $res['status'] ?? 404,
        'message' => $res['error'] ?? 'Tidak ditemukan',
        'raw'     => $res['data'] ?? null
    ];
}

if (!function_exists('satu_get'))  { function satu_get(string $p, ?int $tid=null): array { return satu_request('GET',    $p, null, $tid); } }
if (!function_exists('satu_post')) { function satu_post(string $p, $payload, ?int $tid=null): array { return satu_request('POST',   $p, $payload, $tid); } }
if (!function_exists('satu_put'))  { function satu_put(string $p, $payload, ?int $tid=null): array { return satu_request('PUT',    $p, $payload, $tid); } }
if (!function_exists('satu_delete')){function satu_delete(string $p, $payload=null, ?int $tid=null): array { return satu_request('DELETE', $p, $payload, $tid); } }


/**
 * KFA v2 helpers – pakai token dari helper SATUSEHAT yang sudah ada.
 * - Base URL KFA default: https://api-satusehat-stg.kemkes.go.id
 * - Path KFA: /kfa-v2/...
 */

if (!function_exists('kfa_base_url_from_cfg')) {
    function kfa_base_url_from_cfg(array $cfg): string
    {
        // 1) kalau kamu nanti menambah kolom khusus kfa_base_url di satu_sehat_config, hormati dulu:
        if (!empty($cfg['kfa_base_url'])) {
            return rtrim($cfg['kfa_base_url'], '/');
        }

        // 2) Kalau tidak ada, turunkan dari base_url SATUSEHAT:
        //    hapus suffix /fhir-r4/v1 kalau ada, lalu pakai host yg sama
        $base = trim((string)($cfg['base_url'] ?? ''));
        if ($base === '') return 'https://api-satusehat-stg.kemkes.go.id';

        $base = rtrim($base, '/');
        $base = preg_replace('~/fhir-r4/v1$~i', '', $base); // buang suffix fhir
        return $base ?: 'https://api-satusehat-stg.kemkes.go.id';
    }
}

if (!function_exists('kfa_request')) {
    /**
     * Request ke KFA menggunakan token dari satu_get_token().
     * $path contoh: "/kfa-v2/products/all?page=1&size=50&product_type=farmasi"
     */
    function kfa_request(string $method, string $path, ?int $tenantId = null): array
    {
        $tenantId = $tenantId ?: current_tenant_id();
        $cfg = satu_get_config($tenantId);
        if (!$cfg) {
            return ['success'=>false,'status'=>500,'data'=>null,'error'=>'satu_sehat_config not found'];
        }

        $token = satu_get_token($cfg, $tenantId);
        if (!$token) {
            $why = satu_last_error();
            return ['success'=>false,'status'=>500,'data'=>null,'error'=>'Unable to get SATUSEHAT token'.($why ? " — {$why}" : '')];
        }

        $base = kfa_base_url_from_cfg($cfg); // → host yang sama, tanpa /fhir-r4/v1
        $url  = $base . '/' . ltrim($path, '/');

        $client = \Config\Services::curlrequest(['http_errors'=>false,'timeout'=>40]);
        $res = $client->request(strtoupper($method), $url, [
            'headers' => [
                'Accept'        => 'application/json',
                'Authorization' => 'Bearer '.$token,
            ],
        ]);

        $status = (int)$res->getStatusCode();
        $raw    = (string)$res->getBody();
        $json   = json_decode($raw, true);

        return [
            'success' => $status >= 200 && $status < 300,
            'status'  => $status,
            'data'    => $json ?? ['raw'=>$raw],
            'error'   => $status >= 400 ? ($json['message'] ?? $raw) : null,
        ];
    }
}

if (!function_exists('kfa_get')) {
    function kfa_get(string $path, ?int $tenantId = null): array
    {
        return kfa_request('GET', $path, $tenantId);
    }
}