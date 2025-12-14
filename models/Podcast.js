const mongoose = require('mongoose');

const podcastSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },
  audioUrl: { type: String, required: true }, // Lien fichier MP3
  duration: { type: String }, // Ex: "45:00"
  category: { type: String, default: 'Dourous' }, // Ex: "Tafsir", "Fiqh"
  speaker: { type: String, default: 'Serigne Mor Diop' },
  coverImage: { type: String },
  plays: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

// CORRECTION ICI : On utilise 'Podcast' et on vérifie s'il existe déjà
module.exports = mongoose.models.Podcast || mongoose.model('Podcast', podcastSchema);