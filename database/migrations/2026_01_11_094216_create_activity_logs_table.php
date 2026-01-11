<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('activity_logs', function (Blueprint $table) {
            $table->id();
            // Siapa pelakunya?
            $table->foreignId('user_id')->constrained('users')->onDelete('cascade');
            
            // Ngapain dia? (LOGIN, CREATE_PROJECT, APPLY, REVIEW)
            $table->string('action');
            
            // Detail aktivitasnya
            $table->text('description')->nullable();
            
            $table->timestamps(); // Mencatat kapan kejadiannya
        });
    }

    public function down()
    {
        Schema::dropIfExists('activity_logs');
    }
};