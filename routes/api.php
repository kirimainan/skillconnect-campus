<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\ProjectController;
use App\Http\Controllers\Api\CategoryController;
use App\Http\Controllers\Api\ProjectApplicantController;
use App\Http\Controllers\Api\ReviewController;
use App\Http\Controllers\Api\ActivityLogController; // <--- PASTIKAN ADA INI

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
*/

// AUTH
Route::group(['prefix' => 'auth'], function () {
    Route::post('register', [AuthController::class, 'register']);
    Route::post('login', [AuthController::class, 'login']);
});

// PRIVATE ROUTES (Harus Login / Punya Token)
Route::group(['middleware' => ['auth:api']], function () {

    // AUTH ACTIONS
    Route::get('me', [AuthController::class, 'me']);
    Route::post('logout', [AuthController::class, 'logout']);
    Route::post('refresh', [AuthController::class, 'refresh']);
    Route::post('update-profile', [AuthController::class, 'updateProfile']);
    Route::post('change-password', [AuthController::class, 'changePassword']);

    // CATEGORIES (Admin Only di Controller)
    Route::get('categories', [CategoryController::class, 'index']); // Public read
    Route::post('categories', [CategoryController::class, 'store']);
    Route::get('categories/{id}', [CategoryController::class, 'show']);
    Route::post('categories/{id}', [CategoryController::class, 'update']); // Pakai POST method spoofing buat update
    Route::delete('categories/{id}', [CategoryController::class, 'destroy']);

    // PROJECTS
    Route::get('projects', [ProjectController::class, 'index']);
    Route::post('projects', [ProjectController::class, 'store']); // Client Create
    Route::get('projects/{id}', [ProjectController::class, 'show']);
    Route::post('projects/{id}', [ProjectController::class, 'update']);
    Route::delete('projects/{id}', [ProjectController::class, 'destroy']);

    // BIDDING / LAMARAN
    Route::post('apply-project', [ProjectApplicantController::class, 'store']); // Mahasiswa Melamar
    Route::get('project-applicants/{projectId}', [ProjectApplicantController::class, 'show']); // Client Liat Pelamar
    Route::post('update-application/{id}', [ProjectApplicantController::class, 'update']); // Client Terima/Tolak

    // REVIEWS
    Route::post('reviews', [ReviewController::class, 'store']);
    Route::get('reviews/{userId}', [ReviewController::class, 'show']);
    Route::delete('reviews/{id}', [ReviewController::class, 'destroy']); // Admin Hapus Review

    // --- ACTIVITY LOG (CCTV) ---
    // INI YANG HILANG TADI:
    Route::get('activity-logs', [ActivityLogController::class, 'index']);
});