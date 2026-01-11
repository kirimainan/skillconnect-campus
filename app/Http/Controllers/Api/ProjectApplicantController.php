<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\ProjectApplicant;
use App\Models\Project;
use App\Models\ActivityLog; // <--- WAJIB IMPORT
use Illuminate\Support\Facades\Validator;
use App\Helpers\ApiFormatter;

class ProjectApplicantController extends Controller
{
    // 1. CREATE: Mahasiswa Melamar
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'project_id' => 'required|exists:projects,id',
            'message'    => 'required|string',
            'bid_amount' => 'required|numeric',
        ]);

        if ($validator->fails()) {
            return ApiFormatter::createJson(400, 'Validasi Gagal', $validator->errors());
        }

        // Cek Spam
        $existing = ProjectApplicant::where('project_id', $request->project_id)
            ->where('user_id', auth()->user()->id)
            ->first();

        if ($existing) {
            return ApiFormatter::createJson(409, 'Anda sudah melamar di project ini sebelumnya!');
        }

        $applicant = ProjectApplicant::create([
            'project_id' => $request->project_id,
            'user_id'    => auth()->user()->id,
            'message'    => $request->message,
            'bid_amount' => $request->bid_amount,
            'status'     => 'pending'
        ]);

        // --- CCTV ---
        ActivityLog::create([
            'user_id' => auth()->user()->id,
            'action'  => 'APPLY_PROJECT',
            'description' => 'Melamar project ID: ' . $request->project_id . ' (Bid: ' . $request->bid_amount . ')'
        ]);

        return ApiFormatter::createJson(201, 'Berhasil Melamar Project', $applicant);
    }

    // 2. GET: Lihat Pelamar (Khusus Client Pemilik Project)
    public function show($projectId)
    {
        $project = Project::find($projectId);

        if (!$project) {
            return ApiFormatter::createJson(404, 'Project tidak ditemukan');
        }

        if ($project->client_id !== auth()->user()->id) {
            return ApiFormatter::createJson(403, 'Forbidden: Anda bukan pemilik project ini');
        }

        $applicants = ProjectApplicant::with('user:id,name,email')->where('project_id', $projectId)->get();

        return ApiFormatter::createJson(200, 'List Pelamar Project', $applicants);
    }

    // 3. UPDATE: Terima/Tolak (Khusus Client)
    public function update(Request $request, $id)
    {
        $applicant = ProjectApplicant::with('project')->find($id);

        if (!$applicant) {
            return ApiFormatter::createJson(404, 'Data lamaran tidak ditemukan');
        }

        if ($applicant->project->client_id !== auth()->user()->id) {
            return ApiFormatter::createJson(403, 'Forbidden: Anda tidak berhak mengatur lamaran ini');
        }

        $validator = Validator::make($request->all(), [
            'status' => 'required|in:accepted,rejected'
        ]);

        if ($validator->fails()) {
            return ApiFormatter::createJson(400, 'Status harus accepted atau rejected', $validator->errors());
        }

        $applicant->update([
            'status' => $request->status
        ]);

        // --- CCTV ---
        ActivityLog::create([
            'user_id' => auth()->user()->id,
            'action'  => 'UPDATE_APPLICATION',
            'description' => 'Mengubah status lamaran ID ' . $id . ' menjadi: ' . $request->status
        ]);

        return ApiFormatter::createJson(200, 'Status lamaran berhasil diperbarui', $applicant);
    }
}