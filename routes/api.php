<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\CategoryController; // <--- Pastikan ini ada!\
use App\Http\Controllers\Api\ProjectController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
*/

// 1. PUBLIC (Register & Login)
Route::group(['prefix' => 'auth'], function () {
    Route::post('register', [AuthController::class, 'register']);
    Route::post('login', [AuthController::class, 'login']);
});

// 2. PRIVATE - KHUSUS AUTH (Me, Logout, Refresh)
// URL: /api/auth/me
Route::middleware(['auth:api'])->prefix('auth')->group(function () {
    Route::get('me', [AuthController::class, 'me']);
    Route::post('logout', [AuthController::class, 'logout']);
    Route::post('refresh', [AuthController::class, 'refresh']);
    Route::post('update-profile', [AuthController::class, 'updateProfile']);
});

// 3. PRIVATE - FITUR APLIKASI (Categories, Projects)
// URL: /api/categories (TANPA prefix 'auth')
Route::middleware(['auth:api'])->group(function () {
    
    // Route untuk Category (Miranda)
    Route::apiResource('categories', CategoryController::class);

    // Nanti Project ditaruh sini juga
    Route::apiResource('projects', ProjectController::class);
});