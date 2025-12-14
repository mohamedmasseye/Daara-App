const mongoose = require('mongoose');

const categorySchema = new mongoose.Schema({
  name: { type: String, required: true },
  // CORRECTION : J'ai ajouté 'product' dans la liste enum
  type: { type: String, required: true, enum: ['blog', 'media', 'podcast', 'product'] }, 
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.models.Category || mongoose.model('Category', categorySchema);