<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('reviews', function (Blueprint $table) {
            $table->id();
            // Review ini untuk project apa?
            $table->foreignId('project_id')->constrained('projects')->onDelete('cascade');
            
            // Siapa yang nulis review? (Reviewer)
            $table->foreignId('reviewer_id')->constrained('users')->onDelete('cascade');
            
            // Siapa yang direview? (Target)
            $table->foreignId('reviewee_id')->constrained('users')->onDelete('cascade');
            
            // Bintang 1 sampai 5
            $table->integer('rating');
            
            // Isi ulasan
            $table->text('comment');
            
            $table->timestamps();
        });
    }

    public function down()
    {
        Schema::dropIfExists('reviews');
    }
};