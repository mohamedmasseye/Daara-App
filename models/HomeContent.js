const mongoose = require('mongoose');

const HomeContentSchema = new mongoose.Schema({
  slides: Array,
  about: {
    title1: String,
    highlight1: String,
    title2: String,
    highlight2: String,
    text1: String,
    text2: String,
    image: String,
    bioPdf: String // ✅ Pour le PDF de biographie
  },
  // ✅ Structure mise à jour pour les cartes "Explorez"
  pillars: {
    p1: { image: String, label: String, desc: String, link: String },
    p2: { image: String, label: String, desc: String, link: String },
    p3: { image: String, label: String, desc: String, link: String }
  },
  quote: {
    text: String,
    title: String
  },
  info: {
    address: String,
    hours: String,
    nextGamou: String,
    phone: String,
    contactName: String
  }
}, { timestamps: true });

module.exports = mongoose.model('HomeContent', HomeContentSchema);