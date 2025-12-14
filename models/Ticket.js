const mongoose = require('mongoose');

const ticketSchema = new mongoose.Schema({
  // Liaison obligatoire avec l'événement
  event: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Event', 
    required: true 
  },
  
  // Liaison obligatoire avec l'acheteur
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },

  // Type de billet (Standard, VIP...) - J'ai retiré l'enum strict pour éviter les erreurs
  type: { type: String, default: 'Standard' },

  price: { type: Number, required: true },
  
  // Code unique pour le scan QR
  qrCode: { type: String, unique: true, required: true }, 
  
  // État du billet
  status: { 
    type: String, 
    enum: ['valid', 'used', 'cancelled'], // Minuscules pour être cohérent
    default: 'valid' 
  },
  
  purchaseDate: { type: Date, default: Date.now }
});

module.exports = mongoose.models.Ticket || mongoose.model('Ticket', ticketSchema);