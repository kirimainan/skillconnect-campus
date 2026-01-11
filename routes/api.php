<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

// --- DAFTAR IMPORT (WAJIB ADA DI SINI BIAR GAK ERROR MERAH) ---
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\ReviewController; // <--- TAMBAHKAN INI
use App\Http\Controllers\Api\CategoryController;
use App\Http\Controllers\Api\ProjectController;           // <--- Ini obat error ProjectController
use App\Http\Controllers\Api\ProjectApplicantController;  // <--- Ini obat error ProjectApplicantController

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
*/

// 1. PUBLIC ROUTES (Register & Login)
Route::group(['prefix' => 'auth'], function () {
    Route::post('register', [AuthController::class, 'register']);
    Route::post('login', [AuthController::class, 'login']);
});

// 2. PRIVATE ROUTES - USER AUTH (Logout, Profile, Me)
Route::middleware(['auth:api'])->prefix('auth')->group(function () {
    Route::get('me', [AuthController::class, 'me']);
    Route::post('logout', [AuthController::class, 'logout']);
    Route::post('refresh', [AuthController::class, 'refresh']);
    Route::post('update-profile', [AuthController::class, 'updateProfile']);
    Route::post('change-password', [AuthController::class, 'changePassword']);
});

// 3. PRIVATE ROUTES - FITUR APLIKASI
Route::middleware(['auth:api'])->group(function () {
    
    // --- FITUR MIRANDA ---
    Route::apiResource('categories', CategoryController::class);
    Route::apiResource('projects', ProjectController::class);

    // --- FITUR AFRIZA (BIDDING) ---
    
    // a. Melamar kerja
    Route::post('apply-project', [ProjectApplicantController::class, 'store']);
    
    // b. Lihat pelamar di project tertentu
    Route::get('project-applicants/{projectId}', [ProjectApplicantController::class, 'show']);
    
    // c. Terima/Tolak Lamaran
    Route::post('update-application/{id}', [ProjectApplicantController::class, 'update']);

    // ... rute bidding afriza yg tadi ...

    // --- RUTE REVIEW (AFRIZA) ---
    // 1. Kirim Review (Bintang 1-5)
    Route::post('reviews', [ReviewController::class, 'store']);
    
    // 2. Lihat Review User tertentu (misal: cek reputasi Client/Mahasiswa)
    Route::get('reviews/{userId}', [ReviewController::class, 'show']);
});