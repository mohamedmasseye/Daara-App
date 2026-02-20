const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
  type: { type: String, enum: ['error', 'warning', 'info'], default: 'error' },
  message: String,
  path: String,      // Route qui a planté
  method: String,    // GET, POST, PUT...
  stack: String,     // Détail technique de l'erreur
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Log', logSchema);