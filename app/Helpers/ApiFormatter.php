<?php 

namespace App\Helpers; 

class ApiFormatter 
{ 
    protected static $response = [ 
        'code' => null, 
        'message' => null, 
        'data' => null, 
    ]; 

    public static function createJson($code = null, $message = null, $data = []) 
    { 
        self::$response['code'] = $code; 
        self::$response['message'] = $message; 
        self::$response['data'] = $data; 

        return response()->json(self::$response, self::$response['code']); 
    }
    
    // Tambahan dari Modul 12 (untuk Logging nanti)
    public static function filterSensitiveData(array $data = []): array
    {
        $sensitiveFields = ['password', 'password_confirmation', 'token', 'api_key', 'secret'];

        foreach ($sensitiveFields as $field) {
            if (array_key_exists($field, $data)) {
                $data[$field] = '[FILTERED]';
            }
        }

        return $data;
    }
}