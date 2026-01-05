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
        
        if($token){
            JWTAuth::invalidate($token);
        }

        return response()->json(ApiFormatter::createJson(200, 'Successfully logged out'), 200);
    }
}