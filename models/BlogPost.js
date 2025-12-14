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
  coverImage: { type: String },
  pdfUrl: { type: String }, // <--- NOUVEAU CHAMP : Lien du PDF attaché
  author: { type: String, default: 'Administration' },
  category: { type: String, default: 'Actualité' },
  tags: [String],
  comments: [commentSchema],
  views: { type: Number, default: 0 },
  likes: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.models.BlogPost || mongoose.model('BlogPost', blogPostSchema);