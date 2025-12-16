const mongoose = require('mongoose');

const SlideSchema = new mongoose.Schema({
  id: Number,
  image: String,
  badge: String,
  title: String,
  subtitle: String,
  cta: String,
  link: String
});

const HomeContentSchema = new mongoose.Schema({
  slides: [SlideSchema],
  about: {
    title1: String, highlight1: String,
    title2: String, highlight2: String,
    text1: String, text2: String, image: String
  },
  pillars: {
    shopImage: String, libraryImage: String, mediaImage: String
  },
  quote: { text: String, title: String },
  info: {
    address: String, hours: String,
    nextGamou: String, phone: String, contactName: String
  }
}, { timestamps: true });

module.exports = mongoose.model('HomeContent', HomeContentSchema);