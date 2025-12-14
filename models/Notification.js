const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  title: { type: String, required: true },
  body: { type: String, required: true }, // On garde votre champ "body"
  target: { type: String, default: 'all' },
  
  // 👇 AJOUTEZ JUSTE CETTE LIGNE POUR LES COULEURS
  type: { 
    type: String, 
    enum: ['info', 'warning', 'success', 'alert'], 
    default: 'info' 
  },
  
  date: { type: Date, default: Date.now }, // On garde votre champ "date"
  status: { type: String, default: 'sent' }
});

module.exports = mongoose.model('Notification', notificationSchema);