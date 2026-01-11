<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Category;
use App\Models\ActivityLog; // <--- IMPORT WAJIB
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use App\Helpers\ApiFormatter;

class CategoryController extends Controller
{
    public function index()
    {
        $categories = Category::all();
        return ApiFormatter::createJson(200, 'List Data Kategori', $categories);
    }

    // CREATE (Inject CCTV)
    public function store(Request $request)
    {
        if (auth()->user()->role !== 'admin') {
            return ApiFormatter::createJson(403, 'Forbidden: Hanya Admin yang boleh menambah kategori!');
        }

        $validator = Validator::make($request->all(), [
            'name' => 'required|string|unique:categories,name'
        ]);

        if ($validator->fails()) {
            return ApiFormatter::createJson(400, 'Validasi Gagal', $validator->errors());
        }

        $category = Category::create([
            'name' => $request->name,
            'slug' => Str::slug($request->name)
        ]);

        // --- AFRIZA: LOG ACTIVITY ---
        ActivityLog::create([
            'user_id' => auth()->user()->id,
            'action'  => 'CREATE_CATEGORY',
            'description' => 'Admin membuat kategori baru: ' . $request->name
        ]);
        // ---------------------------

        return ApiFormatter::createJson(201, 'Kategori Berhasil Ditambahkan', $category);
    }

    public function show($id)
    {
        $category = Category::find($id);

        if (!$category) {
            return ApiFormatter::createJson(404, 'Data Kategori Tidak Ditemukan');
        }

        return ApiFormatter::createJson(200, 'Detail Kategori', $category);
    }

    public function update(Request $request, $id)
    {
        if (auth()->user()->role !== 'admin') {
            return ApiFormatter::createJson(403, 'Forbidden: Hanya Admin yang boleh edit kategori!');
        }

        $category = Category::find($id);

        if (!$category) {
            return ApiFormatter::createJson(404, 'Data Kategori Tidak Ditemukan');
        }

        $validator = Validator::make($request->all(), [
            'name' => 'required|string|unique:categories,name,'.$id
        ]);

        if ($validator->fails()) {
            return ApiFormatter::createJson(400, 'Validasi Gagal', $validator->errors());
        }

        $category->update([
            'name' => $request->name,
            'slug' => Str::slug($request->name)
        ]);

        return ApiFormatter::createJson(200, 'Kategori Berhasil Diupdate', $category);
    }

    // DELETE (Inject CCTV)
    public function destroy($id)
    {
        if (auth()->user()->role !== 'admin') {
            return ApiFormatter::createJson(403, 'Forbidden: Hanya Admin yang boleh hapus kategori!');
        }

        $category = Category::find($id);

        if (!$category) {
            return ApiFormatter::createJson(404, 'Data Kategori Tidak Ditemukan');
        }

        $category->delete();

        // --- AFRIZA: LOG ACTIVITY ---
        ActivityLog::create([
            'user_id' => auth()->user()->id,
            'action'  => 'DELETE_CATEGORY',
            'description' => 'Admin menghapus kategori ID ' . $id
        ]);
        // ---------------------------

        return ApiFormatter::createJson(200, 'Kategori Berhasil Dihapus');
    }
}