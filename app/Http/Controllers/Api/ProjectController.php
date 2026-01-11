<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Project;
use App\Models\ActivityLog; // <--- IMPORT WAJIB
use Illuminate\Support\Facades\Validator;
use App\Helpers\ApiFormatter;

class ProjectController extends Controller
{
    public function index()
    {
        $projects = Project::with(['client:id,name,photo', 'category:id,name'])->get();
        return ApiFormatter::createJson(200, 'List Data Project', $projects);
    }

    // CREATE (Inject CCTV)
    public function store(Request $request)
    {
        if (auth()->user()->role !== 'client') {
            return ApiFormatter::createJson(403, 'Forbidden: Hanya akun Client yang boleh memposting lowongan!');
        }

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

        $project = Project::create([
            'client_id'   => auth()->user()->id, 
            'category_id' => $request->category_id,
            'title'       => $request->title,
            'description' => $request->description,
            'budget'      => $request->budget,
            'deadline'    => $request->deadline,
            'status'      => 'open'
        ]);

        // --- AFRIZA: LOG ACTIVITY ---
        ActivityLog::create([
            'user_id' => auth()->user()->id,
            'action'  => 'CREATE_PROJECT',
            'description' => 'Membuat project baru: ' . $request->title
        ]);
        // ---------------------------

        return ApiFormatter::createJson(201, 'Project Berhasil Dibuat', $project);
    }

    public function show($id)
    {
        $project = Project::with(['client', 'category'])->find($id);

        if (!$project) {
            return ApiFormatter::createJson(404, 'Data Project Tidak Ditemukan');
        }

        return ApiFormatter::createJson(200, 'Detail Project', $project);
    }

    // UPDATE (Inject CCTV)
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

        // --- AFRIZA: LOG ACTIVITY ---
        ActivityLog::create([
            'user_id' => auth()->user()->id,
            'action'  => 'UPDATE_PROJECT',
            'description' => 'Update project ID ' . $id
        ]);
        // ---------------------------

        return ApiFormatter::createJson(200, 'Project Berhasil Diupdate', $project);
    }

    // DELETE (Inject CCTV)
    public function destroy($id)
    {
        $project = Project::find($id);

        if (!$project) {
            return ApiFormatter::createJson(404, 'Data Project Tidak Ditemukan');
        }

        $user = auth()->user();

        if ($project->client_id !== $user->id && $user->role !== 'admin') {
            return ApiFormatter::createJson(403, 'Forbidden: Anda tidak punya hak menghapus project ini!');
        }

        $project->delete();

        // --- AFRIZA: LOG ACTIVITY ---
        ActivityLog::create([
            'user_id' => $user->id,
            'action'  => 'DELETE_PROJECT',
            'description' => 'Menghapus project ID ' . $id . ' (Dilakukan oleh role: ' . $user->role . ')'
        ]);
        // ---------------------------

        return ApiFormatter::createJson(200, 'Project Berhasil Dihapus');
    }
}