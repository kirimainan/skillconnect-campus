<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Project extends Model
{
    use HasFactory;

    protected $fillable = [
        'client_id',    // <--- INI YANG TADI KURANG (Penyebab Error)
        'category_id',
        'title',
        'description',
        'budget',
        'deadline',
        'status'
    ];

    // Relasi: Project milik satu Client (User)
    public function client()
    {
        return $this->belongsTo(User::class, 'client_id');
    }

    // Relasi: Project masuk satu Kategori
    public function category()
    {
        return $this->belongsTo(Category::class);
    }
}