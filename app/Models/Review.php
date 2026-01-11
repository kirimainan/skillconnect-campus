<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Review extends Model
{
    use HasFactory;

    protected $fillable = [
        'project_id',
        'reviewer_id',
        'reviewee_id',
        'rating',
        'comment'
    ];

    // Relasi ke User yang menulis review
    public function reviewer()
    {
        return $this->belongsTo(User::class, 'reviewer_id');
    }

    // Relasi ke User yang dinilai
    public function reviewee()
    {
        return $this->belongsTo(User::class, 'reviewee_id');
    }

    // Relasi ke Project
    public function project()
    {
        return $this->belongsTo(Project::class);
    }
}