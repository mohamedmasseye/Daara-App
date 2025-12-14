const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true },
  stock: { type: Number, default: 0 },
  images: [{ type: String }],
  // C'est cette ligne qui fait le lien magique :
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true }, 
  sizes: [{ type: String }],
  colors: [{ type: String }],
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.models.Product || mongoose.model('Product', productSchema);