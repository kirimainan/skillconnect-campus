<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
   public function up(): void
{
    Schema::create('projects', function (Blueprint $table) {
        $table->id();
        $table->foreignId('client_id')->constrained('users')->onDelete('cascade'); // Relasi ke User
        $table->foreignId('category_id')->constrained('categories'); // Relasi ke Kategori
        $table->string('title');
        $table->text('description');
        $table->decimal('budget', 15, 2); // Angka duit
        $table->date('deadline');
        $table->enum('status', ['open', 'in_progress', 'completed', 'closed'])->default('open');
        $table->timestamps();
    });
}
    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('projects');
    }
};
