const mongoose = require('mongoose');

const bookSchema = new mongoose.Schema({
  title: { type: String, required: true },
  author: { type: String, default: 'Serigne Mor Diop' },
  description: { type: String },
  
  // ✅ CORRECTION ICI : On renomme 'coverImageUrl' en 'coverUrl' pour matcher le serveur
  coverUrl: { type: String }, 
  
  pdfUrl: { type: String, required: true },
  category: { type: String },
  downloadCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Book', bookSchema);