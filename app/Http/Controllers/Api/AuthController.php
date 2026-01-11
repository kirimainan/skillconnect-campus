<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Models\User;
use App\Models\ActivityLog; // <--- JANGAN LUPA IMPORT INI LAGI
use Illuminate\Support\Facades\Hash;
use App\Helpers\ApiFormatter;
use Carbon\Carbon;

class AuthController extends Controller
{
    // 1. REGISTER
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name'      => 'required|string|max:255',
            'email'     => 'required|string|email|max:255|unique:users',
            'password'  => 'required|string|min:6',
            'role'      => 'required|in:mahasiswa,client,admin', 
        ]);

        if ($validator->fails()) {
            return ApiFormatter::createJson(400, 'Gagal Validasi', $validator->errors());
        }

        $user = User::create([
            'name'      => $request->name,
            'email'     => $request->email,
            'password'  => Hash::make($request->password),
            'role'      => $request->role,
        ]);

        $token = JWTAuth::fromUser($user);

        return ApiFormatter::createJson(201, 'Register Berhasil', [
            'user'  => $user,
            'token' => $token
        ]);
    }

    // 2. LOGIN (Inject CCTV Disini)
    public function login(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'email'     => 'required|email',
                'password'  => 'required|min:6',
            ]);

            if ($validator->fails()) {
                return response()->json(ApiFormatter::createJson(400, 'Bad Request', $validator->errors()->all()), 400);
            }

            $user = User::where('email', $request->email)->first();
            if (!$user) {
                return response()->json(ApiFormatter::createJson(404, 'Account not found'), 404);
            }

            if (!Hash::check($request->password, $user->password)) {
                return response()->json(ApiFormatter::createJson(401, 'Password does not match'), 401);
            }

            if (!$token = JWTAuth::fromUser($user)) {
                return response()->json(ApiFormatter::createJson(500, 'Failed to generate token'), 500);
            }

            // --- AFRIZA: PASANG CCTV ---
            ActivityLog::create([
                'user_id' => $user->id,
                'action'  => 'LOGIN',
                'description' => 'User (Role: '.$user->role.') berhasil login.'
            ]);
            // --------------------------

            $currentDateTime = Carbon::now();
            $expirationDateTime = $currentDateTime->addSeconds(JWTAuth::factory()->getTTL() * 60);

            $info = [
                'type'    => 'Bearer',
                'token'   => $token,
                'expires' => $expirationDateTime->format('Y-m-d H:i:s')
            ];

            return response()->json(ApiFormatter::createJson(200, 'Login successful', [
                'user' => $user,
                'auth' => $info
            ]), 200);

        } catch (\Exception $e) {
            return response()->json(ApiFormatter::createJson(500, 'Internal Server Error', $e->getMessage()), 500);
        }
    }

    // 3. ME
    public function me()
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            return response()->json(ApiFormatter::createJson(200, 'Logged in User', $user), 200);
        } catch (\Exception $e) {
            return response()->json(ApiFormatter::createJson(401, 'Unauthorized'), 401);
        }
    }

    // 4. REFRESH TOKEN
    public function refresh()
    {
        $currentDateTime = Carbon::now();
        $expirationDateTime = $currentDateTime->addSeconds(JWTAuth::factory()->getTTL() * 60);

        $info = [
            'type'    => 'Bearer',
            'token'   => JWTAuth::refresh(),
            'expires' => $expirationDateTime->format('Y-m-d H:i:s')
        ];

        return response()->json(ApiFormatter::createJson(200, 'Successfully refreshed', $info), 200);
    }

    // 5. LOGOUT
    public function logout()
    {
        $token = JWTAuth::getToken();

        if ($token) {
            JWTAuth::invalidate($token);
        }
        return response()->json(ApiFormatter::createJson(200, 'Successfully logged out'), 200);
    }

    // 6. UPDATE PROFILE (Inject CCTV Disini)
    public function updateProfile(Request $request)
    {
        $user = JWTAuth::parseToken()->authenticate();

        $validator = Validator::make($request->all(), [
            'name'   => 'required|string|max:255',
            'email'  => 'required|email|unique:users,email,' . $user->id,
            'photo'  => 'nullable|image|max:2048',
            'phone'  => 'nullable|string',
            'skills' => 'nullable|string'
        ]);

        if ($validator->fails()) {
            return ApiFormatter::createJson(400, 'Validasi Gagal', $validator->errors());
        }

        if ($request->hasFile('photo')) {
            $path = $request->file('photo')->store('photos', 'public');
            $user->photo = $path;
        }

        $user->name   = $request->name;
        $user->email  = $request->email;
        $user->phone  = $request->phone;
        $user->skills = $request->skills;

        $user->save();

        // --- AFRIZA: PASANG CCTV ---
        ActivityLog::create([
            'user_id' => $user->id,
            'action'  => 'UPDATE_PROFILE',
            'description' => 'User memperbarui data profil.'
        ]);
        // --------------------------

        return ApiFormatter::createJson(200, 'Profile Berhasil Diupdate', $user);
    }

    // 7. CHANGE PASSWORD (Inject CCTV Disini)
    public function changePassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'old_password' => 'required',
            'new_password' => 'required|string|min:6|confirmed' 
        ]);

        if ($validator->fails()) {
            return ApiFormatter::createJson(400, 'Validasi Password Gagal', $validator->errors());
        }

        $user = JWTAuth::parseToken()->authenticate();

        if (!Hash::check($request->old_password, $user->password)) {
            return ApiFormatter::createJson(400, 'Gagal: Password lama tidak sesuai');
        }

        $user->update([
            'password' => Hash::make($request->new_password)
        ]);

        // --- AFRIZA: PASANG CCTV ---
        ActivityLog::create([
            'user_id' => $user->id,
            'action'  => 'CHANGE_PASSWORD',
            'description' => 'User berhasil mengganti password.'
        ]);
        // --------------------------

        return ApiFormatter::createJson(200, 'Password Berhasil Diganti');
    }
}