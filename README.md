🚀 integration-bpjs-satusehat

integration-bpjs-satusehat adalah sebuah helper package untuk mempermudah developer CodeIgniter 4 dalam melakukan integrasi berbagai layanan BPJS & Kemenkes seperti:

🔐 Antrean FKTP (Mobile JKN) – JWT Auth

🏥 BPJS Antrol

💊 BPJS PCare

🔎 BPJS iCare

🏥 SATUSEHAT (FHIR R4)

📦 KFA v2 Kemkes

Helper ini menyederhanakan proses generate signature, timestamp, AES-256 decryption, LZ-string decompress, dan pembuatan token menggunakan JWT untuk layanan antrean.

Package ini didesain agar ringan, reusable, dan mudah dipasang di berbagai project CodeIgniter 4.

✨ FEATURE

Custom base URL setiap layanan

Generate Signature (HMAC-SHA256 BPJS)

Generate Timestamp BPJS otomatis

Auto Encrypt / Decrypt (AES-256-CBC)

Auto-decompress (LZ-String) bila tersedia

Auto-cache token SATUSEHAT

Antrean FKTP JWT Authentication (HS256)

Wrapper GET/POST/PUT/DELETE untuk:
✔ Antrol
✔ PCare
✔ iCare
✔ SATUSEHAT
✔ KFA

📦 Installation

Composer
composer require kamakamanulloh/integration-bpjs-satusehat


Tambahkan dependency JWT:

composer require firebase/php-jwt


Setup Helper (CodeIgniter 4)

Tambahkan helper ke autoload:

app/Config/Autoload.php

public $helpers = ['integration_helper'];


(Optional) Jalankan migration + seeder:

php spark migrate
php spark db:seed IntegrationConfigSeeder

🔧 Environment Configuration

Tambahkan ke .env:

# ========= Antrean FKTP JWT =========
ANTREAN_FKTP_USERNAME = "user_akses_bpjs"
ANTREAN_FKTP_PASSWORD = "password_akses_bpjs"
ANTREAN_FKTP_JWT_SECRET = "secret-random-panjang"
ANTREAN_FKTP_TTL = 3600

# ========= BPJS Antrol =========
BPJS_ANTROL_SECRET_KEY = "secret_key_antrol"
BPJS_ANTROL_SERVICE_NAME = "antrean"

# ========= PCare / Icare =========
BPJS_PCARE_SERVICE_NAME = "pcare"

# ========= SATUSEHAT =========
app.baseURL = "http://localhost:8080/"

🚀 Usage
✔ Antrean FKTP – JWT Auth

Tanpa controller!
app/Config/Routes.php:

$routes->get('auth', function () {
    return antrean_fktp_handle_auth(service('request'), service('response'));
});


Test:

curl -X GET http://localhost:8080/auth \
  -H "x-username: user_akses_bpjs" \
  -H "x-password: password_akses_bpjs"

✔ BPJS Antrol
$res = bpjs_antrol_get("ref/poli/tanggal/2025-12-04");
print_r($res);


POST:

bpjs_antrol_post("antrean/add", [
    "nomorkartu" => "00012345678",
    "nik"        => "3212345678987654",
    "kodepoli"   => "ANA"
]);

✔ PCare
pcare_get("peserta/00012345678/nik");


POST:

pcare_post("pendaftaran", $payload);

✔ iCare
icare_validate_pcare("2200009338321");

✔ SATUSEHAT
satu_patient_by_nik("3201234567890001");

✔ KFA v2
kfa_get("kfa-v2/products/all?page=1&size=50");

📞 Contact

Developed by Kania IT Solution
📱 WA: 089682428590
