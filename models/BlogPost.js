const mongoose = require('mongoose');

const commentSchema = new mongoose.Schema({
  author: { type: String, required: true },
  content: { type: String, required: true },
  date: { type: Date, default: Date.now }
});

const blogPostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true }, // Texte principal
  summary: { type: String },
  
  coverImage: { type: String }, // Correspond bien à server.js
  
  // ✅ CORRECTION ICI : Renommé pour correspondre à votre server.js (Ligne 427)
  pdfDocument: { type: String }, 

  author: { type: String, default: 'Administration' },
  category: { type: String, default: 'Actualité' },
  tags: [String],
  
  // Ces champs sont parfaits pour les likes/comments qu'on a ajoutés
  comments: [commentSchema],
  views: { type: Number, default: 0 },
  likes: { type: Number, default: 0 },
  
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.models.BlogPost || mongoose.model('BlogPost', blogPostSchema);