const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./models/User'); // Assurez-vous que le chemin est bon

// Connexion à la même base de données que server.js
mongoose.connect('mongodb://localhost:27017/daaraserignemordiop')
  .then(() => console.log('✅ Connecté à MongoDB'))
  .catch(err => console.error('❌ Erreur connexion', err));

const createAdmin = async () => {
  try {
    // 1. Supprimer l'ancien admin s'il existe (pour éviter les doublons)
    const email = "admin@daara.com";
    await User.findOneAndDelete({ email });

    // 2. Hasher le mot de passe
    const password = "password123"; // VOTRE MOT DE PASSE
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // 3. Créer le nouvel utilisateur
    const newAdmin = new User({
      fullName: "Super Admin",
      email: email,
      password: hashedPassword,
      phone: "770000000",
      role: "admin" // Si vous avez un champ rôle, sinon il sera ignoré
    });

    await newAdmin.save();
    console.log("🎉 SUCCÈS !");
    console.log(`Email: ${email}`);
    console.log(`Mot de passe: ${password}`);
    
  } catch (error) {
    console.error("Erreur création:", error);
  } finally {
    mongoose.connection.close();
  }
};

createAdmin();