// Gerekli kütüphaneleri içe aktar
const express = require('express');
const { Pool } = require('pg'); 
const cors = require('cors'); 
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000; 

// KESİN ÇÖZÜM: CORS için Netlify adresinizi tanımlıyoruz
const ALLOWED_ORIGIN = 'https://taylorswiftquiz.netlify.app'; 

// Token oluşturmak için kullanılacak gizli anahtar
const JWT_SECRET = process.env.JWT_SECRET || 'cok_gizli_taylor_swift_anahtari'; 

// --- Middleware ---
app.use(express.json()); 
// CORS'u sadece Netlify adresinizden gelen isteklere izin verecek şekilde yapılandırıyoruz
app.use(cors({
    origin: ALLOWED_ORIGIN,
    methods: ['GET', 'POST', 'DELETE']
}));

// --- 1. PostgreSQL Veritabanı Bağlantısı Ayarları ---
const dbConfig = {
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
};

// Yerel test için:
if (process.env.NODE_ENV !== 'production') {
    dbConfig.ssl = false;
}

let pool = new Pool(dbConfig); 

// PostgreSQL'e özel, tek bir tablo oluşturma fonksiyonu
async function setupDatabase() {
    console.log('Veritabanı yapısı kontrol ediliyor...');
    const client = await pool.connect();
    try {
        const schema = `
            CREATE TABLE IF NOT EXISTS Kullanicilar (
                kullanici_id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                sifre_hash VARCHAR(255) NOT NULL,
                rol VARCHAR(20) NOT NULL DEFAULT 'kullanici'
            );
            CREATE TABLE IF NOT EXISTS Sorular (
                soru_id SERIAL PRIMARY KEY,
                soru_metni TEXT NOT NULL,
                fotograf_url VARCHAR(255),
                dogru_cevap_index INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS CevapSiklari (
                cevap_id SERIAL PRIMARY KEY,
                soru_id INTEGER REFERENCES Sorular(soru_id) ON DELETE CASCADE,
                sik_metri VARCHAR(255) NOT NULL,
                sik_index INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS QuizSonuclari (
                sonuc_id SERIAL PRIMARY KEY,
                kullanici_id INTEGER REFERENCES Kullanicilar(kullanici_id),
                dogru_sayisi INTEGER NOT NULL,
                yanlis_sayisi INTEGER NOT NULL,
                sure_saniye INTEGER DEFAULT 0,
                tarih TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `;
        await client.query(schema);
        console.log('✅ Veritabanı yapısı başarılı bir şekilde hazırlandı (veya zaten mevcuttu).');
        
        const adminCheck = await client.query("SELECT COUNT(*) FROM Kullanicilar WHERE rol = 'admin'");
        if (parseInt(adminCheck.rows[0].count) === 0) {
            await client.query("INSERT INTO Kullanicilar (email, sifre_hash, rol) VALUES ('admin@quiz.com', '123456', 'admin')");
            console.log('✅ Varsayılan admin kullanıcısı eklendi.');
        }

    } finally {
        client.release();
    }
}

setupDatabase();


// --- Rota Fonksiyonları (Sorgular PostgreSQL'e uyarlanmıştır) ---

// --- 2. YENİ KULLANICI KAYIT ROTASI ---
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) { return res.status(400).json({ success: false, message: 'E-posta ve şifre gereklidir.' }); }
    try {
        const existingUsers = await pool.query('SELECT email FROM Kullanicilar WHERE email = $1', [email]);
        if (existingUsers.rows.length > 0) { return res.status(409).json({ success: false, message: 'Bu e-posta zaten kullanımda.' }); }
        const result = await pool.query("INSERT INTO Kullanicilar (email, sifre_hash, rol) VALUES ($1, $2, 'kullanici') RETURNING kullanici_id", [email, password]);
        res.status(201).json({ success: true, message: 'Kayıt başarılı! Giriş yapabilirsiniz.', userId: result.rows[0].kullanici_id });
    } catch (error) {
        console.error('Kayıt hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası.' });
    }
});


// --- 3. GİRİŞ (LOGIN) ROTASI ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const users = await pool.query('SELECT * FROM Kullanicilar WHERE email = $1', [email]);
        const user = users.rows[0];
        if (!user) { return res.status(401).json({ success: false, message: 'Kullanıcı bulunamadı.' }); }
        if (password === user.sifre_hash) { 
            const token = jwt.sign(
                { kullanici_id: user.kullanici_id, rol: user.rol, email: user.email }, 
                JWT_SECRET, 
                { expiresIn: '1h' }
            );
            return res.json({ success: true, message: 'Giriş başarılı!', token: token, rol: user.rol, email: user.email });
        } else {
            return res.status(401).json({ success: false, message: 'Yanlış şifre.' });
        }
    } catch (error) {
        console.error('Giriş hatası:', error);
        return res.status(500).json({ success: false, message: 'Sunucu hatası.' });
    }
});


// --- Yetkilendirme (Auth) Middleware'i ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) { return res.status(401).json({ success: false, message: 'Giriş yapınız.' }); }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) { return res.status(403).json({ success: false, message: 'Geçersiz veya süresi dolmuş token.' }); }
        req.user = user; 
        next();
    });
};

// --- 4. SORU EKLEME ROTASI ---
app.post('/api/admin/add-question', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') { return res.status(403).json({ success: false, message: 'Yetkisiz erişim. Sadece adminler soru ekleyebilir.' }); }
    const { soru_metni, fotograf_url, cevap_siklari, dogru_cevap_index } = req.body;
    if (!soru_metni || !cevap_siklari || !dogru_cevap_index || cevap_siklari.length !== 4) {
        return res.status(400).json({ success: false, message: 'Tüm alanlar (4 şık dahil) gereklidir.' });
    }
    try {
        const client = await pool.connect();
        await client.query('BEGIN');
        try {
            const result = await client.query('INSERT INTO Sorular (soru_metni, fotograf_url, dogru_cevap_index) VALUES ($1, $2, $3) RETURNING soru_id', [soru_metni, fotograf_url || null, dogru_cevap_index]);
            const newSoruId = result.rows[0].soru_id;
            for (let i = 0; i < cevap_siklari.length; i++) {
                await client.query('INSERT INTO CevapSiklari (soru_id, sik_metri, sik_index) VALUES ($1, $2, $3)', [newSoruId, cevap_siklari[i], i + 1]);
            }
            await client.query('COMMIT');
            client.release();
            res.json({ success: true, message: 'Soru ve şıklar başarıyla eklendi.', soru_id: newSoruId });
        } catch (error) {
            await client.query('ROLLBACK');
            client.release();
            throw error; 
        }
    } catch (error) {
        console.error('Soru ekleme hatası:', error);
        res.status(500).json({ success: false, message: 'Soru eklenirken bir sunucu hatası oluştu.' });
    }
});


// --- 5. SORU SİLME ROTASI ---
app.delete('/api/admin/delete-question/:soru_id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') { return res.status(403).json({ success: false, message: 'Yetkisiz erişim. Sadece adminler soru silebilir.' }); }
    const soruId = req.params.soru_id;
    try {
        const result = await pool.query('DELETE FROM Sorular WHERE soru_id = $1', [soruId]);
        if (result.rowCount === 0) { return res.status(404).json({ success: false, message: 'Silinecek soru bulunamadı.' }); }
        res.json({ success: true, message: `Soru ID: ${soruId} başarıyla silindi.` });
    } catch (error) {
        console.error('Soru silme hatası:', error);
        res.status(500).json({ success: false, message: 'Soru silinirken sunucu hatası oluştu.' });
    }
});


// --- 6. QUIZ SORULARINI ÇEKME ROTASI ---
app.get('/api/quiz/questions', async (req, res) => {
    try {
        const questionsResult = await pool.query('SELECT soru_id, soru_metni, fotograf_url FROM Sorular ORDER BY RANDOM()');
        let questions = questionsResult.rows;
        for (const question of questions) {
            const choicesResult = await pool.query('SELECT sik_index, sik_metri FROM CevapSiklari WHERE soru_id = $1 ORDER BY sik_index', [question.soru_id]);
            question.siklar = choicesResult.rows;
        }
        res.json({ success: true, questions: questions });
    } catch (error) {
        console.error('Soru çekme hatası:', error);
        res.status(500).json({ success: false, message: 'Sorular yüklenemedi.' });
    }
});


// --- 7. QUIZ SONUÇLARINI KAYDETME ROTASI ---
app.post('/api/quiz/submit', authenticateToken, async (req, res) => {
    const kullanici_id = req.user.kullanici_id; 
    const { dogru_sayisi, yanlis_sayisi, sure_saniye } = req.body; 
    try {
        const result = await pool.query('INSERT INTO QuizSonuclari (kullanici_id, dogru_sayisi, yanlis_sayisi, sure_saniye) VALUES ($1, $2, $3, $4) RETURNING sonuc_id', [kullanici_id, dogru_sayisi, yanlis_sayisi, sure_saniye]);
        res.json({ success: true, message: 'Quiz sonuçları başarıyla kaydedildi.', sonuc_id: result.rows[0].sonuc_id });
    } catch (error) {
        console.error('Sonuç kaydetme hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası.' });
    }
});


// --- 8. ADMIN SONUÇLARI GÖRÜNTÜLEME ROTASI ---
app.get('/api/admin/results', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') { return res.status(403).json({ success: false, message: 'Yetkisiz erişim.' }); }
    try {
        const results = await pool.query(`
            SELECT QS.sonuc_id, U.email, QS.dogru_sayisi, QS.yanlis_sayisi, QS.tarih, QS.sure_saniye
            FROM QuizSonuclari AS QS JOIN Kullanicilar AS U ON QS.kullanici_id = U.kullanici_id
            ORDER BY QS.tarih DESC
        `);
        res.json({ success: true, results: results.rows });
    } catch (error) {
        console.error('Sonuçları çekme hatası:', error);
        res.status(500).json({ success: false, message: 'Sonuçlar yüklenirken sunucu hatası oluştu.' });
    }
});


// --- 9. LEADERBOARD ROTASI ---
app.get('/api/admin/leaderboard', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') { return res.status(403).json({ success: false, message: 'Yetkisiz erişim.' }); }
    try {
        const leaderboard = await pool.query(`
            SELECT U.email, QS.dogru_sayisi, (QS.dogru_sayisi + QS.yanlis_sayisi) AS toplam_soru, QS.sure_saniye
            FROM QuizSonuclari AS QS JOIN Kullanicilar AS U ON QS.kullanici_id = U.kullanici_id
            ORDER BY QS.dogru_sayisi DESC, QS.sure_saniye ASC, QS.tarih DESC
            LIMIT 50 
        `);
        res.json({ success: true, leaderboard: leaderboard.rows });
    } catch (error) {
        console.error('Leaderboard hatası:', error);
        res.status(500).json({ success: false, message: 'Liderlik tablosu yüklenemedi.' });
    }
});


// --- 10. Temel Test Rotası ---
app.get('/', (req, res) => {
    res.send('Taylor Swift Quiz Sitesi Arka Yüzü Başarılı ve Çalışıyor!');
});


// Sunucuyu başlatma
app.listen(port, () => {
    console.log(`🚀 Sunucu şu adreste çalışıyor: https://taylor-swift-quiz-site.onrender.com`);
});
