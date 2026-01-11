<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\ActivityLog;
use App\Helpers\ApiFormatter;

class ActivityLogController extends Controller
{
    // Lihat Riwayat Aktivitas Saya
    public function index()
    {
        // Ambil log milik user yang sedang login, urutkan dari yang terbaru
        $logs = ActivityLog::where('user_id', auth()->user()->id)
            ->orderBy('created_at', 'desc')
            ->get();

        return ApiFormatter::createJson(200, 'Riwayat Aktivitas User', $logs);
    }
}