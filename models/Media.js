const mongoose = require('mongoose');

const mediaSchema = new mongoose.Schema({
  title: { type: String, required: true },
  type: { type: String, enum: ['photo', 'video'], required: true },
  url: { type: String, required: true }, // URL de l'image ou lien YouTube/Fichier
  thumbnail: { type: String }, // Pour les vidéos
  category: { type: String, required: true }, // Ex: "Ziarra 2024", "Gamou"
  date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Media', mediaSchema);