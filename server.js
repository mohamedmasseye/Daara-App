const fs = require('fs');
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// ==========================================
// 0. CONFIGURATION FIREBASE (NOUVEAU)
// ==========================================
const admin = require('firebase-admin');
// On vérifie si le fichier existe pour éviter de faire planter le serveur s'il manque
try {
  const serviceAccount = require('./serviceAccountKey.json');
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log("🔥 Firebase Admin connecté avec succès !");
} catch (error) {
  console.log("⚠️ Attention : serviceAccountKey.json manquant ou invalide.");
  console.log("   => Les notifications mobiles ne fonctionneront pas, mais le reste OUI.");
}

// ==========================================
// 1. IMPORTS DES MODÈLES (Vérifiés)
// ==========================================
const User = require('./models/User');
const Event = require('./models/Event');
const Order = require('./models/Order');
const Ticket = require('./models/Ticket');
const Product = require('./models/Product');
const Category = require('./models/Category');
const BlogPost = require('./models/BlogPost');
const Podcast = require('./models/Podcast');
const Book = require('./models/Book');
const Media = require('./models/Media');
const Notification = require('./models/Notification');
const Contact = require('./models/Contact');

const app = express();
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Serveur démarré sur le port ${PORT}`));

// Dossier Uploads
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// Middlewares
const allowedOrigins = [
  'https://daaraserignemordiop.vercel.app/', // REMPLACEZ CETTE VALEUR PAR VOTRE VRAIE URL VERCEL
  'http://localhost:3000',                  // Utile pour vos tests locaux
  'http://localhost:5000'                 // Utile si le front est sur 5000
];

const corsOptions = {
  origin: function (origin, callback) {
    // Autoriser les origines dans la liste, ou s'il n'y a pas d'origine (mobile, Postman)
    if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
      callback(null, true)
    } else {
      callback(new Error('Not allowed by CORS'))
    }
  },
  credentials: true, // IMPORTANT si vous utilisez des cookies ou des sessions
};
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors(corsOptions));
app.use(express.json());
app.use('/uploads', express.static(uploadDir));

// ==========================================
// 2. CONFIGURATION UPLOADS (Multer)
// ==========================================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    // Nettoyage du nom de fichier
    const cleanName = file.originalname.replace(/[^a-zA-Z0-9.]/g, "_");
    cb(null, Date.now() + '-' + cleanName);
  }
});
const upload = multer({ storage: storage });

// Configurations spécifiques pour chaque type
const productUploads = upload.array('productImages', 5);
const eventUploads = upload.fields([{ name: 'eventImage', maxCount: 1 }, { name: 'eventDocument', maxCount: 1 }]);
const podcastUploads = upload.fields([{ name: 'audioFile', maxCount: 1 }, { name: 'coverImageFile', maxCount: 1 }]);
const bookUploads = upload.fields([{ name: 'pdfFile', maxCount: 1 }, { name: 'coverImage', maxCount: 1 }]);
const blogUploads = upload.fields([{ name: 'coverImageFile', maxCount: 1 }, { name: 'pdfDocumentFile', maxCount: 1 }]);
const mediaUploads = upload.single('mediaFile');
const avatarUpload = upload.single('avatar');

const JWT_SECRET = 'daara_secret_key_super_securisee_123';

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: "Accès refusé" });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token invalide" });
    req.user = user;
    next();
  });
};

// Utilitaire URL Fichier
const getFileUrl = (req, filename) => filename ? `https://${req.get('host')}/uploads/${filename}` : null;
// ==========================================
// 3. ROUTES API
// ==========================================

// --- AUTHENTIFICATION (Version Intelligente) ---
const handleLogin = async (req, res) => {
    try { 
        // 1. On récupère TOUT ce qui peut arriver (identifier OU email)
        const { identifier, email, password } = req.body; 
        
        // 2. On détermine quelle est la clé de connexion
        // Si "identifier" est vide, on utilise "email"
        const loginKey = identifier || email;

        if (!loginKey) {
             return res.status(400).json({ error: "Email ou Téléphone requis." });
        }
        
        // 3. Recherche : On cherche dans email OU phone
        const user = await User.findOne({ 
            $or: [
                { email: loginKey }, 
                { phone: loginKey }
            ] 
        }); 

        // 4. Vérification du mot de passe
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: "Identifiant ou mot de passe incorrect." }); 
        }
        
        // 5. Création du Token
        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' }); 
        res.json({ token, user }); 

    } catch (err) { 
        console.error(err);
        res.status(500).json({ error: err.message }); 
    } 
};

app.post('/api/auth/login', handleLogin);
app.post('/api/login', handleLogin); 

// MODIFICATION DE LA ROUTE REGISTER DANS SERVER.JS

app.post('/api/auth/register', async (req, res) => { 
    try { 
        // On ne reçoit plus "email" et "phone" séparément, mais "identifier"
        const { fullName, identifier, password } = req.body; 
        
        if (!identifier) {
            return res.status(400).json({ error: "L'email ou le téléphone est requis." });
        }

        // --- INTELLIGENCE : DÉTECTION DU TYPE ---
        // Si ça contient un "@", c'est un email. Sinon, on considère que c'est un téléphone.
        const isEmail = identifier.includes('@');
        
        const email = isEmail ? identifier : undefined;
        const phone = !isEmail ? identifier : undefined;

        // --- VÉRIFICATION DES DOUBLONS ---
        if (isEmail) {
            const exists = await User.findOne({ email });
            if (exists) return res.status(400).json({ error: "Cet email est déjà inscrit." });
        } else {
            const exists = await User.findOne({ phone });
            if (exists) return res.status(400).json({ error: "Ce numéro est déjà inscrit." });
        }

        // Cryptage
        const hashedPassword = await bcrypt.hash(password, 10); 
        
        // --- CRÉATION ---
        await new User({ 
            fullName, 
            email: email, 
            phone: phone, 
            password: hashedPassword 
        }).save(); 
        
        res.status(201).json({ message: "Compte créé avec succès !" }); 

    } catch (err) { 
        console.error(err);
        res.status(500).json({ error: "Erreur serveur lors de l'inscription." }); 
    } 
});

// --- CONNEXION VIA GOOGLE (MOBILE & WEB) ---
app.post('/api/auth/google', async (req, res) => {
    try {
        const { token } = req.body; // Le token envoyé par le téléphone (Google)
        
        if (!token) return res.status(400).json({ error: "Token Google manquant" });

        // 1. On demande à Firebase de vérifier l'identité
        const decodedToken = await admin.auth().verifyIdToken(token);
        const { uid, email, name, picture } = decodedToken;

        // 2. On cherche si l'utilisateur existe déjà chez nous
        let user = await User.findOne({ 
            $or: [
                { googleId: uid }, 
                { email: email } 
            ] 
        });

        // 3. S'il n'existe pas, on le CRÉE (Inscription Automatique)
        if (!user) {
            user = new User({
                fullName: name || "Utilisateur Google",
                email: email,
                googleId: uid,
                avatar: picture,
                authProvider: 'google',
                role: 'user',
                // Pas de password car c'est Google qui gère
            });
            await user.save();
        } else {
            // S'il existe, on met à jour son Google ID et sa photo si besoin
            if (!user.googleId) user.googleId = uid;
            if (!user.avatar) user.avatar = picture;
            if (user.authProvider === 'local') user.authProvider = 'google'; // On lie les comptes
            await user.save();
        }

        // 4. On génère NOTRE token à nous (JWT) pour la suite
        const appToken = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });

        res.json({ token: appToken, user });

    } catch (err) {
        console.error("Erreur Google Auth:", err);
        res.status(401).json({ error: "Authentification Google échouée" });
    }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => { 
    try { const user = await User.findById(req.user.id).select('-password'); res.json(user); } 
    catch (err) { res.status(500).json({ error: err.message }); } 
});

// MISE À JOUR PROFIL (AVEC PHOTO)
app.put('/api/auth/me', authenticateToken, avatarUpload, async (req, res) => {
  try {
    const { fullName, bio, city, phone } = req.body;

    // Objet de mise à jour
    let updateData = { 
        fullName, 
        bio, 
        city, 
        phone 
    };

    // Si une nouvelle photo est envoyée, on l'ajoute
    if (req.file) {
        updateData.avatar = getFileUrl(req, req.file.filename);
    }

    const updatedUser = await User.findByIdAndUpdate(
        req.user.id,
        updateData,
        { new: true }
    ).select('-password');

    res.json(updatedUser);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erreur lors de la mise à jour du profil." });
  }
});

// --- GESTION UTILISATEURS (ADMIN) ---

// 1. Lister tous les utilisateurs (Déjà fait, mais on s'assure qu'il est là)
app.get('/api/users', authenticateToken, async (req, res) => {
    try { const users = await User.find().select('-password').sort({ createdAt: -1 }); res.json(users); } 
    catch (err) { res.status(500).json({ error: err.message }); }
});

// 2. Créer un utilisateur (Par l'Admin)
app.post('/api/users', authenticateToken, async (req, res) => {
    try {
        const { fullName, identifier, password, role } = req.body;
        
        // Détection Email ou Tel
        const isEmail = identifier.includes('@');
        const email = isEmail ? identifier : undefined;
        const phone = !isEmail ? identifier : undefined;

        // Vérif doublon
        const exists = await User.findOne({ $or: [{ email: identifier }, { phone: identifier }] });
        if (exists) return res.status(400).json({ error: "Cet utilisateur existe déjà." });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            fullName,
            email,
            phone,
            password: hashedPassword,
            role: role || 'user'
        });
        await newUser.save();
        res.status(201).json(newUser);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 3. Modifier un utilisateur (Rôle, Nom...)
app.put('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const { fullName, role, bio, city } = req.body;
        const updatedUser = await User.findByIdAndUpdate(
            req.params.id, 
            { fullName, role, bio, city }, 
            { new: true }
        ).select('-password');
        res.json(updatedUser);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 4. Reset Mot de Passe (Par l'Admin)
app.put('/api/users/:id/reset-password', authenticateToken, async (req, res) => {
    try {
        const { newPassword } = req.body;
        if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: "Mot de passe trop court." });
        
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await User.findByIdAndUpdate(req.params.id, { password: hashedPassword });
        
        res.json({ message: "Mot de passe réinitialisé avec succès." });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 5. Supprimer (Déjà fait)
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
    try { await User.findByIdAndDelete(req.params.id); res.json({ message: "Utilisateur supprimé" }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// --- PRODUITS ---
app.get('/api/products', async (req, res) => {
    try { const products = await Product.find().populate('category').sort({ createdAt: -1 }); res.json(products); } 
    catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/products', productUploads, async (req, res) => {
    try {
        const imageUrls = (req.files || []).map(f => getFileUrl(req, f.filename));
        const { name, description, price, stock, category } = req.body;
        const newProduct = new Product({ name, description, price, stock, category, images: imageUrls });
        await newProduct.save();
        res.status(201).json(newProduct);
    } catch (err) { res.status(400).json({ error: err.message }); }
});
app.put('/api/products/:id', productUploads, async (req, res) => {
    try {
        let updateData = { ...req.body };
        if (req.files && req.files.length > 0) {
            updateData.images = req.files.map(f => getFileUrl(req, f.filename));
        }
        const updatedProduct = await Product.findByIdAndUpdate(req.params.id, updateData, { new: true });
        res.json(updatedProduct);
    } catch (err) { res.status(400).json({ error: err.message }); }
});
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    try { await Product.findByIdAndDelete(req.params.id); res.json({ message: "Supprimé" }); } 
    catch (err) { res.status(500).json({ error: err.message }); }
});

// --- CATÉGORIES (CORRIGÉ) ---

// 1. Récupérer par type (POUR LE FRONTEND : /api/categories/podcast)
app.get('/api/categories/:type', async (req, res) => {
  try {
    const { type } = req.params;
    const categories = await Category.find({ type }).sort({ name: 1 });
    res.json(categories);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Récupérer tout ou filtre (POUR COMPATIBILITÉ)
app.get('/api/categories', async (req, res) => {
  try {
    const { type } = req.query;
    const filter = type ? { type } : {};
    const categories = await Category.find(filter).sort({ name: 1 });
    res.json(categories);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// 3. Créer une catégorie (RETOURNE L'OBJET COMPLET)
app.post('/api/categories', authenticateToken, async (req, res) => {
  try {
    const { name, type } = req.body;
    // Majuscule automatique
    const formattedName = name.charAt(0).toUpperCase() + name.slice(1);
    
    const newCategory = new Category({ name: formattedName, type: type || 'product' });
    await newCategory.save();
    
    // IMPORTANT : On renvoie l'objet créé (avec _id) pour l'affichage immédiat
    res.status(201).json(newCategory);
  } catch (err) { 
    if (err.code === 11000) return res.status(400).json({ error: "Existe déjà" });
    res.status(400).json({ error: "Erreur création" }); 
  }
});

// 4. Modifier
app.put('/api/categories/:id', authenticateToken, async (req, res) => {
  try { await Category.findByIdAndUpdate(req.params.id, { name: req.body.name }); res.json({ message: "Modifié" }); } 
  catch (err) { res.status(400).json({ error: "Erreur" }); }
});

// 5. Supprimer
app.delete('/api/categories/:id', authenticateToken, async (req, res) => {
  try { await Category.findByIdAndDelete(req.params.id); res.json({ message: "Supprimé" }); } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- ÉVÉNEMENTS ---
app.get('/api/events', async (req, res) => { 
    try { const events = await Event.find().sort({ date: 1 }); res.json(events); } 
    catch (err) { res.status(500).json({ error: err.message }); } 
});
app.post('/api/events', eventUploads, async (req, res) => { 
  try { 
    const img = req.files['eventImage']?.[0];
    const doc = req.files['eventDocument']?.[0];
    const evt = new Event({ 
        ...req.body, 
        image: getFileUrl(req, img?.filename), 
        documentUrl: getFileUrl(req, doc?.filename) 
    });
    await evt.save(); 
    res.status(201).json(evt); 
  } catch(err){ res.status(400).json({error: err.message}); } 
});
app.put('/api/events/:id', eventUploads, async (req, res) => {
  try {
    let updateData = { ...req.body };
    const img = req.files['eventImage']?.[0];
    const doc = req.files['eventDocument']?.[0];
    if (img) updateData.image = getFileUrl(req, img.filename);
    if (doc) updateData.documentUrl = getFileUrl(req, doc.filename);
    const updatedEvent = await Event.findByIdAndUpdate(req.params.id, updateData, { new: true });
    res.json(updatedEvent);
  } catch (err) { res.status(400).json({ error: err.message }); }
});
app.delete('/api/events/:id', authenticateToken, async (req, res) => { 
    try { await Event.findByIdAndDelete(req.params.id); res.json({message: "Supprimé"}); } 
    catch(err) { res.status(500).json({error: err.message}); } 
});

// --- PODCASTS ---
app.get('/api/podcasts', async (req, res) => {
    try { const podcasts = await Podcast.find().sort({ createdAt: -1 }); res.json(podcasts); } 
    catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/podcasts', podcastUploads, async (req, res) => {
    try {
        const audio = req.files['audioFile']?.[0];
        const cover = req.files['coverImageFile']?.[0];
        if (!audio) return res.status(400).json({ error: "Audio requis" });
        const podcast = new Podcast({ ...req.body, audioUrl: getFileUrl(req, audio.filename), coverImage: getFileUrl(req, cover?.filename) });
        await podcast.save();
        res.status(201).json(podcast);
    } catch (err) { res.status(400).json({ error: err.message }); }
});
app.delete('/api/podcasts/:id', authenticateToken, async (req, res) => {
    try { await Podcast.findByIdAndDelete(req.params.id); res.json({ message: "Supprimé" }); } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- LIVRES ---
app.get('/api/books', async (req, res) => {
    try { const books = await Book.find().sort({ createdAt: -1 }); res.json(books); } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/books', bookUploads, async (req, res) => {
    try {
        const pdf = req.files['pdfFile']?.[0];
        const cover = req.files['coverImage']?.[0];
        const book = new Book({ ...req.body, pdfUrl: pdf ? getFileUrl(req, pdf.filename) : req.body.pdfUrl, coverUrl: getFileUrl(req, cover?.filename) });
        await book.save();
        res.status(201).json(book);
    } catch (err) { res.status(400).json({ error: err.message }); }
});
app.delete('/api/books/:id', authenticateToken, async (req, res) => {
    try { await Book.findByIdAndDelete(req.params.id); res.json({ message: "Supprimé" }); } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- BLOG ---
app.get('/api/blog', async (req, res) => {
    try { const posts = await BlogPost.find().sort({ createdAt: -1 }); res.json(posts); } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/blog', blogUploads, async (req, res) => {
    try {
        const cover = req.files['coverImageFile']?.[0];
        const pdf = req.files['pdfDocumentFile']?.[0];
        const post = new BlogPost({ ...req.body, coverImage: getFileUrl(req, cover?.filename), pdfDocument: getFileUrl(req, pdf?.filename) });
        await post.save();
        res.status(201).json(post);
    } catch (err) { res.status(400).json({ error: err.message }); }
});
app.delete('/api/blog/:id', authenticateToken, async (req, res) => {
    try { await BlogPost.findByIdAndDelete(req.params.id); res.json({ message: "Supprimé" }); } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- GALERIE (MEDIA) ---
app.get('/api/media', async (req, res) => {
    try { const media = await Media.find().sort({ createdAt: -1 }); res.json(media); } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/media', mediaUploads, async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "Fichier requis" });
        const media = new Media({ ...req.body, url: getFileUrl(req, req.file.filename) });
        await media.save();
        res.status(201).json(media);
    } catch (err) { res.status(400).json({ error: err.message }); }
});
app.delete('/api/media/:id', authenticateToken, async (req, res) => {
    try { await Media.findByIdAndDelete(req.params.id); res.json({ message: "Supprimé" }); } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- COMMANDES & BILLETS (Création & Gestion Admin) ---
app.post('/api/orders', authenticateToken, async (req, res) => {
  try {
    const { user, items, totalAmount, paymentMethod, customerPhone, address } = req.body;
    let cleanPayment = paymentMethod;
    if (paymentMethod && paymentMethod.toLowerCase().includes('wave')) cleanPayment = 'Wave';
    if (paymentMethod && (paymentMethod.toLowerCase().includes('orange') || paymentMethod === 'om')) cleanPayment = 'Orange Money';

    const newOrder = new Order({ user, items, totalAmount, paymentMethod: cleanPayment, customerPhone, address: address || {}, status: 'Pending' });
    const savedOrder = await newOrder.save();

    const ticketItems = items.filter(item => item.type === 'ticket');
    if (ticketItems.length > 0) {
        for (const item of ticketItems) {
            const eventId = item.ticketEvent || item.product;
            if (eventId) {
                for (let i = 0; i < item.quantity; i++) {
                    await new Ticket({ event: eventId, user: user, type: 'Standard', price: item.price, qrCode: `TKT-${savedOrder._id.toString().slice(-6)}-${Date.now()}-${i}` }).save();
                }
            }
        }
    }
    res.status(201).json(savedOrder);
  } catch (err) { res.status(400).json({ error: err.message }); }
});
app.get('/api/orders', async (req, res) => { 
    try { const orders = await Order.find().populate('user', 'fullName email').sort({ createdAt: -1 }); res.json(orders); } 
    catch (err) { res.status(500).json({ error: err.message }); } 
});
app.delete('/api/orders/:id', authenticateToken, async (req, res) => { 
    try { await Ticket.deleteMany({ qrCode: { $regex: req.params.id } }); await Order.findByIdAndDelete(req.params.id); res.json({ message: "Supprimée" }); } 
    catch (err) { res.status(500).json({ error: err.message }); } 
});

// --- AJOUT : MISE À JOUR STATUT COMMANDE ---
app.put('/api/orders/:id', authenticateToken, async (req, res) => {
  try {
    const { status } = req.body;
    // On met à jour uniquement le statut
    const updatedOrder = await Order.findByIdAndUpdate(
      req.params.id, 
      { status: status }, 
      { new: true } // Renvoie la nouvelle version
    );
    res.json(updatedOrder);
  } catch (err) { 
    res.status(400).json({ error: "Impossible de mettre à jour le statut." }); 
  }
});

// --- GESTION DES NOTIFICATIONS ---

// 1. Récupérer toutes les notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        // On trie par "date" (votre champ)
        const notifications = await Notification.find().sort({ date: -1 });
        res.json(notifications);
    } catch (err) {
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// 2. Créer / Envoyer une notification (AVEC FIREBASE PUSH)
app.post('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const { title, body, type, target } = req.body;
        
        // A. Sauvegarde en Base de Données (Historique pour l'Admin)
        const newNotif = new Notification({ 
            title, 
            body, 
            type: type || 'info', 
            target 
        });
        await newNotif.save();

        // B. Envoi Réel via Firebase (Le Nuage)
        // On envoie sur le canal "all_users". 
        // L'application mobile s'abonnera à ce canal dès son installation.
        if (admin.apps.length) {
            const message = {
                notification: {
                    title: title,
                    body: body,
                },
                topic: 'all_users' // <-- C'est ici que la magie opère
            };
            
            admin.messaging().send(message)
                .then((response) => console.log('✈️ Notification Push envoyée ! ID:', response))
                .catch((error) => console.log('⚠️ Erreur envoi Firebase:', error.message));
        }

        res.status(201).json(newNotif);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// 3. Supprimer une notification
app.delete('/api/notifications/:id', authenticateToken, async (req, res) => {
    try {
        await Notification.findByIdAndDelete(req.params.id);
        res.json({ message: "Notification supprimée" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
// --- ROUTES PROFIL CLIENT ---
app.get('/api/my-orders', authenticateToken, async (req, res) => { 
    try { const orders = await Order.find({ user: req.user.id }).sort({ createdAt: -1 }); res.json(orders); } 
    catch (err) { res.status(500).json({ error: err.message }); } 
});
app.get('/api/my-tickets', authenticateToken, async (req, res) => { 
    try { const tickets = await Ticket.find({ user: req.user.id }).populate('event').sort({ createdAt: -1 }); res.json(tickets); } 
    catch (err) { res.status(500).json({ error: err.message }); } 
});
// LA CORRECTION : Route pour supprimer un billet individuel
app.delete('/api/tickets/:id', authenticateToken, async (req, res) => {
    try { await Ticket.findByIdAndDelete(req.params.id); res.json({ message: "Billet supprimé" }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// --- UPLOAD GÉNÉRIQUE (Pour l'Admin Home) ---
app.post('/api/upload', upload.single('file'), (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "Aucun fichier envoyé" });
        // On renvoie l'URL complète de l'image
        const fileUrl = getFileUrl(req, req.file.filename);
        res.json({ url: fileUrl });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- MESSAGERIE / CONTACT ---

// 1. Envoyer un message (PUBLIC - Pas besoin de token car c'est le visiteur qui écrit)
app.post('/api/contact', async (req, res) => {
    try {
        const { name, emailOrPhone, message } = req.body;
        const newMessage = new Contact({ name, emailOrPhone, message });
        await newMessage.save();
        res.status(201).json({ message: "Message envoyé avec succès." });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// 2. Lire les messages (ADMIN - Besoin du token)
app.get('/api/contact', authenticateToken, async (req, res) => {
    try {
        const messages = await Contact.find().sort({ date: -1 }); // Plus récents en premier
        res.json(messages);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. Supprimer un message
app.delete('/api/contact/:id', authenticateToken, async (req, res) => {
    try {
        await Contact.findByIdAndDelete(req.params.id);
        res.json({ message: "Message supprimé." });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// 4. LANCEMENT ET AUTO-CONFIG
// ==========================================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://mohamedmasseye_db_user:Kmd789415!@cluster0.1clqeei.mongodb.net/daaraserignemordiop?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGODB_URI)
  .then(async () => {
    console.log('✅ Connecté à MongoDB ATLAS (En ligne)');
    
    // Création Admin Auto (Reste inchangé)
    try {
        const adminEmail = "admin@daara.com";
        const adminExist = await User.findOne({ email: adminEmail });
        if (!adminExist) {
            const hashedPassword = await bcrypt.hash("password123", 10);
            await new User({ fullName: "Super Admin", email: adminEmail, password: hashedPassword, phone: "770000000", role: "admin" }).save();
            console.log("🎉 ADMIN CRÉÉ ! Email: admin@daara.com / Pass: password123");
        }
    } catch (e) { console.error("Erreur admin auto:", e); }
    
    // Pour Render/Heroku, il faut écouter sur 0.0.0.0
    app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Serveur en ligne sur le port ${PORT}`));
  })
  .catch(err => console.error('❌ Erreur MongoDB:', err));