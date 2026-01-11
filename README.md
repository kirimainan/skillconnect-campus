<div align="center">
<h1>SkillConnect Campus</h1>
</div>

## Deskripsi Singkat
SkillConnect Campus adalah

## Requirements

Pastikan Anda telah menginstal hal-hal berikut pada sistem Anda:

```
Git (2.51.2 atau lebih baru)
Composer (2.9.1 atau lebih baru)
XAMPP (8.2.12)
```

## Cara Menjalankan Sistem

1. Clone Repo

```
git clone https://github.com/kirimainan/skillconnect-campus.git
cd skillconnect-campus
```

2. Install dependency:

```
composer install
```

3. Setup Environment:

```
Ubah .env.example -> .env
Atur Koneksi DB & MYSQL (DB_DATABASE, dll jika diperlukan)
```
> [!NOTE]
> Klik dibawah ini untuk apa saja yang diubah pada .env
<details>
<summary>Klik disini!</summary>

```
Ubah menjadi seperti ini:
DB_CONNECTION=mysql # ubah sqlite ke mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=skillconnect # sesuaikan dengan database,
DB_USERNAME=root
DB_PASSWORD=''
```

</details>

4. Migration:

```
php artisan migrate
```

5. Setup JWT (tymon/jwt-auth): **Projectnya gunain JWT kan bg Davin?**

```
composer require tymon/jwt-auth
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider" (membuat config/jwt.php)
php artisan jwt:secret (mengisi JWT_SECRET di .env)
```

6. Jalankan Local Development Server:

```
php artisan serve
```

## Dokumentasi API
- Postman Collection (publish): (isi disini bg Davin)