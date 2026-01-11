<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Review;
use App\Models\ActivityLog; // <--- WAJIB IMPORT
use Illuminate\Support\Facades\Validator;
use App\Helpers\ApiFormatter;

class ReviewController extends Controller
{
    // 1. CREATE: Berikan Review
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'project_id'  => 'required|exists:projects,id',
            'reviewee_id' => 'required|exists:users,id',
            'rating'      => 'required|integer|min:1|max:5',
            'comment'     => 'required|string',
        ]);

        if ($validator->fails()) {
            return ApiFormatter::createJson(400, 'Validasi Gagal', $validator->errors());
        }

        // Cek Double Review
        $existingReview = Review::where('project_id', $request->project_id)
            ->where('reviewer_id', auth()->user()->id)
            ->where('reviewee_id', $request->reviewee_id)
            ->first();

        if ($existingReview) {
            return ApiFormatter::createJson(409, 'Anda sudah memberikan review untuk user ini di project ini!');
        }

        $review = Review::create([
            'project_id'  => $request->project_id,
            'reviewer_id' => auth()->user()->id,
            'reviewee_id' => $request->reviewee_id,
            'rating'      => $request->rating,
            'comment'     => $request->comment,
        ]);

        // --- CCTV ---
        ActivityLog::create([
            'user_id' => auth()->user()->id,
            'action'  => 'GIVE_REVIEW',
            'description' => 'Memberikan rating ' . $request->rating . ' Bintang kepada user ID: ' . $request->reviewee_id
        ]);

        return ApiFormatter::createJson(201, 'Review Berhasil Dikirim', $review);
    }

    // 2. GET: Lihat Review User
    public function show($userId)
    {
        $reviews = Review::with(['reviewer:id,name', 'project:id,title'])
            ->where('reviewee_id', $userId)
            ->get();

        return ApiFormatter::createJson(200, 'List Review User', $reviews);
    }

    // 3. DELETE: Hapus Review (Fitur Admin & Pemilik)
    public function destroy($id)
    {
        $review = Review::find($id);

        if (!$review) {
            return ApiFormatter::createJson(404, 'Review tidak ditemukan');
        }

        $user = auth()->user(); 

        // LOGIC SAKTI: 
        // Kalau BUKAN Admin DAN BUKAN Penulisnya -> TENDANG!
        if ($user->role !== 'admin' && $user->id !== $review->reviewer_id) {
            return ApiFormatter::createJson(403, 'Forbidden: Anda tidak berhak menghapus review ini');
        }

        $review->delete();

        // --- CCTV (Catat siapa yang menghapus) ---
        $desc = ($user->role === 'admin') 
            ? 'Admin menghapus review ID: ' . $id 
            : 'User menghapus review sendiri ID: ' . $id;

        ActivityLog::create([
            'user_id' => $user->id,
            'action'  => 'DELETE_REVIEW',
            'description' => $desc
        ]);

        return ApiFormatter::createJson(200, 'Review Berhasil Dihapus');
    }
}