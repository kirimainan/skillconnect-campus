<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
*/

// --- 1. PUBLIC ROUTES (Bisa diakses siapa saja: Register & Login) ---
// Prefix 'auth' membuat URL jadi: /api/auth/register & /api/auth/login
Route::group(['prefix' => 'auth'], function () {
    Route::post('register', [AuthController::class, 'register']);
    Route::post('login', [AuthController::class, 'login']);
});

// --- 2. PRIVATE ROUTES (Harus Login / Punya Token) ---
// Middleware 'auth:api' mengecek token
// Prefix 'auth' membuat URL jadi: /api/auth/me & /api/auth/logout
Route::middleware(['auth:api'])->prefix('auth')->group(function () {
    Route::get('me', [AuthController::class, 'me']);      // <--- INI YANG KAMU CARI
    Route::post('update-profile', [AuthController::class, 'updateProfile']);
    Route::post('logout', [AuthController::class, 'logout']);
    Route::post('refresh', [AuthController::class, 'refresh']);
});