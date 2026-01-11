<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Review;
use Illuminate\Support\Facades\Validator;
use App\Helpers\ApiFormatter;

class ReviewController extends Controller
{
    // 1. CREATE: Berikan Review (Rating & Comment)
    public function store(Request $request)
    {
        // Validasi Input
        $validator = Validator::make($request->all(), [
            'project_id'  => 'required|exists:projects,id',
            'reviewee_id' => 'required|exists:users,id', // ID orang yang mau dinilai
            'rating'      => 'required|integer|min:1|max:5', // Wajib 1 sampai 5
            'comment'     => 'required|string',
        ]);

        if ($validator->fails()) {
            return ApiFormatter::createJson(400, 'Validasi Gagal', $validator->errors());
        }

        // Cek: Jangan sampai user review 2x di project yang sama untuk orang yang sama
        $existingReview = Review::where('project_id', $request->project_id)
            ->where('reviewer_id', auth()->user()->id)
            ->where('reviewee_id', $request->reviewee_id)
            ->first();

        if ($existingReview) {
            return ApiFormatter::createJson(409, 'Anda sudah memberikan review untuk user ini di project ini!');
        }

        // Simpan Review
        $review = Review::create([
            'project_id'  => $request->project_id,
            'reviewer_id' => auth()->user()->id, // Otomatis pakai ID yang login
            'reviewee_id' => $request->reviewee_id,
            'rating'      => $request->rating,
            'comment'     => $request->comment,
        ]);

        return ApiFormatter::createJson(201, 'Review Berhasil Dikirim', $review);
    }

    // 2. GET: Lihat semua review milik user tertentu (Buat Profil)
    // Contoh URL: /api/reviews/5 (Lihat review punya user ID 5)
    public function show($userId)
    {
        $reviews = Review::with(['reviewer:id,name', 'project:id,title'])
            ->where('reviewee_id', $userId)
            ->get();

        return ApiFormatter::createJson(200, 'List Review User', $reviews);
    }
}