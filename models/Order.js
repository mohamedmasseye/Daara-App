const mongoose = require('mongoose');

const orderItemSchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' }, // Si c'est un produit
  ticketEvent: { type: mongoose.Schema.Types.ObjectId, ref: 'Event' }, // Si c'est un ticket
  type: { type: String, enum: ['product', 'ticket'], required: true },
  name: { type: String, required: true }, // On garde le nom au cas où le produit est supprimé
  quantity: { type: Number, default: 1 },
  price: { type: Number, required: true }, // Prix unitaire au moment de l'achat
  options: { type: String } // Ex: "Taille: L, Couleur: Blanc"
});

const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [orderItemSchema],
  
  totalAmount: { type: Number, required: true },
  
  paymentMethod: {
    type: String,
    enum: ['Wave', 'Orange Money', 'Cash', 'wave', 'om', 'orange money'], // Ajoutez les variantes en minuscules ici
    required: true
  },
  paymentStatus: { type: String, enum: ['Pending', 'Paid', 'Failed'], default: 'Pending' },

  // --- NOUVEAU : Adresse complète ---
  address: {
    city: { type: String, default: '' },
    neighborhood: { type: String, default: '' }, // Quartier
    details: { type: String, default: '' }       // Instructions sup.
  },

  // --- NOUVEAU : Statut du cycle de vie (Timeline) ---
  // Pending    : Commande reçue / Validée
  // Processing : En cours de préparation
  // Shipping   : En cours de livraison
  // Delivered  : Livrée / Terminée
  // Cancelled  : Annulée
  status: { 
    type: String, 
    enum: ['Pending', 'Processing', 'Shipping', 'Delivered', 'Cancelled'], 
    default: 'Pending' 
  },

  customerPhone: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.models.Order || mongoose.model('Order', orderSchema);