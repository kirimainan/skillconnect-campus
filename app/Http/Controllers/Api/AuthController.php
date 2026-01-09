<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Models\User; // Pastikan User diimport
use Illuminate\Support\Facades\Hash;
use App\Helpers\ApiFormatter;
use Carbon\Carbon;

class AuthController extends Controller
{
    // 1. FITUR REGISTER (Bikin Akun Baru)
    public function register(Request $request)
    {
        // Validasi input
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
            'role' => 'required|in:mahasiswa,client', // Validasi role
        ]);

        if ($validator->fails()) {
            return ApiFormatter::createJson(400, 'Gagal Validasi', $validator->errors());
        }

        // Simpan User ke Database
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password), // Password wajib di-hash
            'role' => $request->role,
        ]);

        // Langsung buatkan token JWT untuk user baru ini
        $token = JWTAuth::fromUser($user);

        // Return response JSON rapi
        return ApiFormatter::createJson(201, 'Register Berhasil', [
            'user' => $user,
            'token' => $token
        ]);
    }
    public function login(Request $request)
    {
        try {
            $params = $request->all();

            $validator = Validator::make($params, [
                'email' => 'required|email',
                'password' => 'required|min:6',
            ], [
                'email.required' => 'Email is required',
                'email.email' => 'Email must be a valid email address',
                'password.required' => 'Password is required',
                'password.min' => 'Password must be at least :min characters',
            ]);

            if ($validator->fails()) {
                return response()->json(ApiFormatter::createJson(400, 'Bad Request', $validator->errors()->all()), 400);
            }

            // Cari user berdasarkan email
            $user = User::where('email', $params['email'])->first();
            if (!$user) {
                return response()->json(ApiFormatter::createJson(404, 'Account not found'), 404);
            }

            // Periksa password
            if (!Hash::check($params['password'], $user->password)) {
                return response()->json(ApiFormatter::createJson(401, 'Password does not match'), 401);
            }

            // Generate token JWT
            if (!$token = JWTAuth::fromUser($user)) {
                return response()->json(ApiFormatter::createJson(500, 'Failed to generate token'), 500);
            }

            // Informasi token
            $currentDateTime = Carbon::now();
            $expirationDateTime = $currentDateTime->addSeconds(JWTAuth::factory()->getTTL() * 60);

            $info = [
                'type' => 'Bearer',
                'token' => $token,
                'expires' => $expirationDateTime->format('Y-m-d H:i:s')
            ];

            return response()->json(ApiFormatter::createJson(200, 'Login successful', $info), 200);

        } catch (\Exception $e) {
            return response()->json(ApiFormatter::createJson(500, 'Internal Server Error', $e->getMessage()), 500);
        }
    }

    public function me()
    {
        $user = JWTAuth::parseToken()->authenticate();
        $token = JWTAuth::getToken();
        $payload = JWTAuth::getPayload($token);

        $expiration = $payload->get('exp');
        $expiration_time = date('Y-m-d H:i:s', $expiration);

        $data['name'] = $user['name'];
        $data['email'] = $user['email'];
        $data['exp'] = $expiration_time;

        return response()->json(ApiFormatter::createJson(200, 'Logged in User', $data), 200);
    }

    public function refresh()
    {
        $currentDateTime = Carbon::now();
        $expirationDateTime = $currentDateTime->addSeconds(JWTAuth::factory()->getTTL() * 60);

        $info = [
            'type' => 'Bearer',
            'token' => JWTAuth::refresh(),
            'expires' => $expirationDateTime->format('Y-m-d H:i:s')
        ];

        return response()->json(ApiFormatter::createJson(200, 'Successfully refreshed', $info), 200);
    }

    public function logout()
    {
        // GANTI baris ini:
        // JWTAuth::logout();

        // MENJADI ini:
        $token = JWTAuth::getToken();

        if ($token) {
            JWTAuth::invalidate($token);
        }

        return response()->json(ApiFormatter::createJson(200, 'Successfully logged out'), 200);
    }
    // 6. UPDATE PROFILE (Foto & Password)
    public function updateProfile(Request $request)
    {
        $user = auth()->user(); // Ambil user yang sedang login

        // Validasi input
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email,' . $user->id, // Email boleh sama kalau punya sendiri
            'password' => 'nullable|min:6',        // Password opsional (kalau gak mau ganti)
            'photo' => 'nullable|image|max:2048', // Foto opsional, max 2MB
            'phone' => 'nullable|string',
            'skills' => 'nullable|string'
        ]);

        if ($validator->fails()) {
            return ApiFormatter::createJson(400, 'Validasi Gagal', $validator->errors());
        }

        // Logic Upload Foto
        if ($request->hasFile('photo')) {
            // Simpan file ke folder: storage/app/public/photos
            $path = $request->file('photo')->store('photos', 'public');
            $user->photo = $path; // Simpan path-nya ke database
        }

        // Update data text
        $user->name = $request->name;
        $user->email = $request->email;
        $user->phone = $request->phone;
        $user->skills = $request->skills;

        // Cek apakah user kirim password baru?
        if ($request->filled('password')) {
            $user->password = Hash::make($request->password);
        }

        $user->save(); // Simpan perubahan ke DB

        return ApiFormatter::createJson(200, 'Profile Berhasil Diupdate', $user);
    }
}
