<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('project_applicants', function (Blueprint $table) {
            $table->id();
            // Project mana yang dilamar?
            $table->foreignId('project_id')->constrained('projects')->onDelete('cascade');
            
            // Siapa yang melamar? (Mahasiswa)
            $table->foreignId('user_id')->constrained('users')->onDelete('cascade');
            
            // Pesan/Surat Lamaran
            $table->text('message');
            
            // Harga Tawar (Bidding)
            $table->decimal('bid_amount', 15, 2);
            
            // Status: Menunggu, Diterima, Ditolak
            $table->enum('status', ['pending', 'accepted', 'rejected'])->default('pending');
            
            $table->timestamps();
        });
    }

    public function down()
    {
        Schema::dropIfExists('project_applicants');
    }
};