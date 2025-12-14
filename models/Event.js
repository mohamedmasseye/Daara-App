const mongoose = require('mongoose');

const eventSchema = new mongoose.Schema({
  // --- INFOS DE BASE ---
  title: { type: String, required: true },
  description: { type: String },
  date: { type: Date, required: true },
  location: { type: String },
  locationLink: { type: String },
  isOnline: { type: Boolean, default: false },
  
  // --- MÉDIAS ---
  image: { type: String },      // URL de l'affiche
  documentUrl: { type: String }, // URL du programme PDF
  
  // --- BILLETTERIE (IMPORTANT) ---
  // On met les deux noms pour éviter les bugs si tu as des anciennes versions
  hasTicket: { type: Boolean, default: false }, 
  
  // Le nouveau standard (utilisé par AdminEvents.jsx)
  price: { type: Number, default: 0 }, 
  stock: { type: Number, default: 0 },

  // Les anciens champs (au cas où)
  ticketPrice: { type: Number, default: 0 },
  ticketStock: { type: Number, default: 0 },
  
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.models.Event || mongoose.model('Event', eventSchema);