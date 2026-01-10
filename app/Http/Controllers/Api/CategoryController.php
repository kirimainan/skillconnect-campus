<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\Category;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use App\Helpers\ApiFormatter;

class CategoryController extends Controller
{
    // 1. GET: Tampilkan Semua Kategori
    public function index()
    {
        $categories = Category::all();

        return ApiFormatter::createJson(200, 'List Data Kategori', $categories);
    }

    // 2. POST: Tambah Kategori Baru (INI YANG HILANG TADI)
    public function store(Request $request)
    {
        // Validasi Input
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|unique:categories,name'
        ]);

        if ($validator->fails()) {
            return ApiFormatter::createJson(400, 'Validasi Gagal', $validator->errors());
        }

        // Simpan Data
        $category = Category::create([
            'name' => $request->name,
            'slug' => Str::slug($request->name)
        ]);

        return ApiFormatter::createJson(201, 'Kategori Berhasil Ditambahkan', $category);
    }

    // 3. GET: Detail Kategori
    public function show($id)
    {
        $category = Category::find($id);

        if (!$category) {
            return ApiFormatter::createJson(404, 'Data Kategori Tidak Ditemukan');
        }

        return ApiFormatter::createJson(200, 'Detail Kategori', $category);
    }

    // 4. PUT: Update Kategori
    public function update(Request $request, $id)
    {
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

    // 5. DELETE: Hapus Kategori
    public function destroy($id)
    {
        $category = Category::find($id);

        if (!$category) {
            return ApiFormatter::createJson(404, 'Data Kategori Tidak Ditemukan');
        }

        $category->delete();

        return ApiFormatter::createJson(200, 'Kategori Berhasil Dihapus');
    }
}