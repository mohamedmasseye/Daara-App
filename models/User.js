const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  
  // Email n'est plus "required" strict car on peut s'inscrire par téléphone
  email: { type: String, unique: true, sparse: true }, 
  
  // Téléphone
  phone: { type: String, unique: true, sparse: true },
  
  // Mot de passe (Pas obligatoire si on se connecte via Google)
  password: { type: String }, 
  
  // Rôle (user, admin, superadmin...)
  role: { type: String, default: 'user' },
  
  // Infos Profil
  bio: { type: String, default: '' },
  city: { type: String, default: '' },
  avatar: { type: String, default: '' },

  // --- NOUVEAUX CHAMPS POUR L'APPLI MOBILE ---
  
  // 1. Pour l'inscription Google
  googleId: { type: String, unique: true, sparse: true },
  
  // 2. Type d'inscription ('local' = email/pass, 'google' = gmail)
  authProvider: { 
    type: String, 
    enum: ['local', 'google'], 
    default: 'local' 
  },

  // 3. Pour les NOTIFICATIONS PUSH (Firebase)
  // C'est l'adresse unique du téléphone de l'utilisateur
  fcmToken: { type: String, default: '' },

  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);