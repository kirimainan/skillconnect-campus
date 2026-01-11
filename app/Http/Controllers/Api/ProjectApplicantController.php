<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\ProjectApplicant;
use App\Models\Project;
use Illuminate\Support\Facades\Validator;
use App\Helpers\ApiFormatter;

class ProjectApplicantController extends Controller
{
    // 1. CREATE: Mahasiswa Melamar Pekerjaan
    public function store(Request $request)
    {
        // Validasi Input
        $validator = Validator::make($request->all(), [
            'project_id' => 'required|exists:projects,id',
            'message'    => 'required|string',
            'bid_amount' => 'required|numeric',
        ]);

        if ($validator->fails()) {
            return ApiFormatter::createJson(400, 'Validasi Gagal', $validator->errors());
        }

        // Cek apakah user sudah pernah melamar di project ini? (Biar gak spam)
        $existing = ProjectApplicant::where('project_id', $request->project_id)
            ->where('user_id', auth()->user()->id)
            ->first();

        if ($existing) {
            return ApiFormatter::createJson(409, 'Anda sudah melamar di project ini sebelumnya!');
        }

        // Simpan Lamaran
        $applicant = ProjectApplicant::create([
            'project_id' => $request->project_id,
            'user_id'    => auth()->user()->id, // Otomatis ambil ID user yg login
            'message'    => $request->message,
            'bid_amount' => $request->bid_amount,
            'status'     => 'pending'
        ]);

        return ApiFormatter::createJson(201, 'Berhasil Melamar Project', $applicant);
    }

    // 2. GET: Lihat List Pelamar di Project tertentu (Hanya Pemilik Project yang boleh lihat)
    public function show($projectId)
    {
        $project = Project::find($projectId);

        if (!$project) {
            return ApiFormatter::createJson(404, 'Project tidak ditemukan');
        }

        // Validasi: Yang boleh lihat pelamar cuma pemilik project
        if ($project->client_id !== auth()->user()->id) {
            return ApiFormatter::createJson(403, 'Forbidden: Anda bukan pemilik project ini');
        }

        $applicants = ProjectApplicant::with('user:id,name,email')->where('project_id', $projectId)->get();

        return ApiFormatter::createJson(200, 'List Pelamar Project', $applicants);
    }

    // 3. UPDATE: Client Menerima/Menolak Lamaran
    public function update(Request $request, $id)
    {
        // Cari data lamaran berdasarkan ID
        $applicant = ProjectApplicant::with('project')->find($id);

        if (!$applicant) {
            return ApiFormatter::createJson(404, 'Data lamaran tidak ditemukan');
        }

        // Validasi: Pastikan yang nge-ACC adalah pemilik project
        if ($applicant->project->client_id !== auth()->user()->id) {
            return ApiFormatter::createJson(403, 'Forbidden: Anda tidak berhak mengatur lamaran ini');
        }

        // Validasi Status yang dikirim
        $validator = Validator::make($request->all(), [
            'status' => 'required|in:accepted,rejected'
        ]);

        if ($validator->fails()) {
            return ApiFormatter::createJson(400, 'Status harus accepted atau rejected', $validator->errors());
        }

        // Update Status
        $applicant->update([
            'status' => $request->status
        ]);

        return ApiFormatter::createJson(200, 'Status lamaran berhasil diperbarui', $applicant);
    }
}