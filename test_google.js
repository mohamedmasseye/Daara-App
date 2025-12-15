const axios = require('axios');

async function testGoogleRoute() {
  console.log("🚀 Envoi d'une demande de connexion Google simulée...");

  try {
    // On envoie un FAUX token.
    // Si le serveur est bien configuré, il va demander à Firebase : "C'est quoi ça ?"
    // Et Firebase va répondre : "C'est un faux token !" => Erreur 401.
    const reponse = await axios.post('https://daara-app.onrender.com/api/auth/google', {
      token: "ceci_est_un_faux_token_google_pour_le_test"
    });

    console.log("Réponse inattendue (ça ne devrait pas marcher avec un faux token):", reponse.data);

  } catch (error) {
    if (error.response) {
      // C'est ICI qu'on vérifie si ça marche
      if (error.response.status === 401) {
        console.log("✅ SUCCÈS !");
        console.log("Le serveur a bien reçu la demande, a interrogé Firebase, et a rejeté le faux token.");
        console.log("La route est fonctionnelle et sécurisée.");
      } else if (error.response.status === 404) {
        console.log("❌ ÉCHEC : Erreur 404. La route n'existe pas dans server.js.");
      } else {
        console.log("⚠️ Autre erreur :", error.response.status, error.response.data);
      }
    } else {
      console.log("❌ Erreur de connexion au serveur (Vérifiez qu'il tourne bien sur le port 5000).");
    }
  }
}

testGoogleRoute();