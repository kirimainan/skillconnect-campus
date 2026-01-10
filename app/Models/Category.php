<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Category extends Model
{
    use HasFactory;

    protected $table = 'categories'; // Opsional, tapi bagus biar jelas

    // --- INI YANG KURANG TADI ---
    // Kita harus mengizinkan kolom 'name' dan 'slug' untuk diisi
    protected $fillable = [
        'name',
        'slug'
    ];

    // Relasi ke Project (buat persiapan nanti)
    public function projects()
    {
        return $this->hasMany(Project::class);
    }
}