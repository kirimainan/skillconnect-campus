<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Project;
use Illuminate\Support\Facades\Validator;
use App\Helpers\ApiFormatter;

class ProjectController extends Controller
{
    // 1. GET ALL: Tampilkan semua lowongan
    public function index()
    {
        $projects = Project::with(['client:id,name,photo', 'category:id,name'])->get();

        return ApiFormatter::createJson(200, 'List Data Project', $projects);
    }

    // 2. CREATE: Tambah Lowongan (INI YANG ERROR TADI)
    public function store(Request $request)
    {
        // Cek Role: Kalau bukan 'client', tolak!
        if (auth()->user()->role !== 'client') {
            return ApiFormatter::createJson(403, 'Forbidden: Hanya Client yang boleh membuat project!');
        }

        // Validasi Input
        $validator = Validator::make($request->all(), [
            'category_id' => 'required|exists:categories,id',
            'title'       => 'required|string|max:255',
            'description' => 'required|string',
            'budget'      => 'required|numeric',
            'deadline'    => 'required|date',
        ]);

        if ($validator->fails()) {
            return ApiFormatter::createJson(400, 'Validasi Gagal', $validator->errors());
        }

        // Simpan Project
        $project = Project::create([
            'client_id'   => auth()->user()->id, 
            'category_id' => $request->category_id,
            'title'       => $request->title,
            'description' => $request->description,
            'budget'      => $request->budget,
            'deadline'    => $request->deadline,
            'status'      => 'open'
        ]);

        return ApiFormatter::createJson(201, 'Project Berhasil Dibuat', $project);
    }

    // 3. SHOW: Detail satu lowongan
    public function show($id)
    {
        $project = Project::with(['client', 'category'])->find($id);

        if (!$project) {
            return ApiFormatter::createJson(404, 'Data Project Tidak Ditemukan');
        }

        return ApiFormatter::createJson(200, 'Detail Project', $project);
    }

    // 4. UPDATE: Edit Lowongan
    public function update(Request $request, $id)
    {
        $project = Project::find($id);

        if (!$project) {
            return ApiFormatter::createJson(404, 'Data Project Tidak Ditemukan');
        }

        if ($project->client_id !== auth()->user()->id) {
            return ApiFormatter::createJson(403, 'Forbidden: Anda bukan pemilik project ini!');
        }

        $project->update($request->all());

        return ApiFormatter::createJson(200, 'Project Berhasil Diupdate', $project);
    }

    // 5. DELETE: Hapus Lowongan
    public function destroy($id)
    {
        $project = Project::find($id);

        if (!$project) {
            return ApiFormatter::createJson(404, 'Data Project Tidak Ditemukan');
        }

        if ($project->client_id !== auth()->user()->id) {
            return ApiFormatter::createJson(403, 'Forbidden: Anda bukan pemilik project ini!');
        }

        $project->delete();

        return ApiFormatter::createJson(200, 'Project Berhasil Dihapus');
    }
}