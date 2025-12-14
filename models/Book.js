const mongoose = require('mongoose');

const bookSchema = new mongoose.Schema({
  title: { type: String, required: true },
  author: { type: String, default: 'Serigne Mor Diop' },
  description: { type: String },
  coverImageUrl: { type: String }, // Lien vers l'image de couverture
  pdfUrl: { type: String, required: true }, // Lien vers le fichier PDF
  category: { type: String }, // Ex: "Conférences", "Tawhid", etc.
  downloadCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Book', bookSchema);