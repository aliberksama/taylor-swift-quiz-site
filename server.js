// Gerekli kütüphaneleri içe aktar
const express = require('express');
const mysql = require('mysql2/promise'); 
const cors = require('cors'); 
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000; 

// Token oluşturmak için kullanılacak gizli anahtar
const JWT_SECRET = 'cok_gizli_taylor_swift_anahtari'; 

// --- Middleware ---
app.use(express.json()); 
app.use(cors()); // CORS'u aktif et

// Veritabanı bağlantısı global olarak tanımlanıyor
let pool;

// --- 1. MySQL Veritabanı Bağlantısı Ayarları ---
const dbConfig = {
    host: 'localhost',      
    user: 'root',           
    password: '2004', // <-- KESİNLİKLE KENDİ ŞİFRENİZ OLDUĞUNDAN EMİN OLUN
    database: 'taylor_quiz_db' 
};

// Veritabanı bağlantı havuzunu başlatma
async function initializeDatabase() {
    try {
        pool = await mysql.createPool(dbConfig);
        console.log('✅ MySQL veritabanına başarılı bir şekilde bağlanıldı!');

        const [rows] = await pool.query('SELECT 1 + 1 AS solution');
        console.log('Veritabanı test sonucu:', rows[0].solution);

    } catch (err) {
        console.error('❌ Veritabanı bağlantı hatası:', err.message);
        console.error('MySQL şifrenizin ve servisinizin çalıştığından emin olun!');
        process.exit(1);
    }
}

// --- Yetkilendirme (Auth) Middleware'i ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: Bearer TOKEN

    if (token == null) {
        return res.status(401).json({ success: false, message: 'Giriş yapınız.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Geçersiz veya süresi dolmuş token.' });
        }
        req.user = user; 
        next();
    });
};


// --- 2. YENİ KULLANICI KAYIT ROTASI ---
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'E-posta ve şifre gereklidir.' });
    }

    try {
        const [existingUsers] = await pool.query('SELECT email FROM Kullanicilar WHERE email = ?', [email]);

        if (existingUsers.length > 0) {
            return res.status(409).json({ success: false, message: 'Bu e-posta zaten kullanımda.' });
        }

        const sifre_hash = password; 
        
        const [result] = await pool.query(
            'INSERT INTO Kullanicilar (email, sifre_hash, rol) VALUES (?, ?, ?)',
            [email, sifre_hash, 'kullanici']
        );

        res.status(201).json({ success: true, message: 'Kayıt başarılı! Giriş yapabilirsiniz.', userId: result.insertId });

    } catch (error) {
        console.error('Kayıt hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası.' });
    }
});


// --- 3. GİRİŞ (LOGIN) ROTASI ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [users] = await pool.query('SELECT * FROM Kullanicilar WHERE email = ?', [email]);
        const user = users[0];
        if (!user) { return res.status(401).json({ success: false, message: 'Kullanıcı bulunamadı.' }); }

        if (password === user.sifre_hash) { 
            
            const token = jwt.sign(
                { kullanici_id: user.kullanici_id, rol: user.rol, email: user.email }, 
                JWT_SECRET, 
                { expiresIn: '1h' }
            );

            return res.json({ 
                success: true, 
                message: 'Giriş başarılı!', 
                token: token, 
                rol: user.rol,
                email: user.email 
            });
        } else {
            return res.status(401).json({ success: false, message: 'Yanlış şifre.' });
        }

    } catch (error) {
        console.error('Giriş hatası:', error);
        return res.status(500).json({ success: false, message: 'Sunucu hatası.' });
    }
});


// --- 4. SORU EKLEME ROTASI (Admin Yetkilendirmesi Gerekir) ---
app.post('/api/admin/add-question', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') { 
        return res.status(403).json({ success: false, message: 'Yetkisiz erişim. Sadece adminler soru ekleyebilir.' }); 
    }

    const { soru_metni, fotograf_url, cevap_siklari, dogru_cevap_index } = req.body;

    if (!soru_metni || !cevap_siklari || !dogru_cevap_index || cevap_siklari.length !== 4) {
        return res.status(400).json({ success: false, message: 'Tüm alanlar (4 şık dahil) gereklidir.' });
    }

    try {
        const connection = await pool.getConnection();
        await connection.beginTransaction();

        try {
            const [result] = await connection.execute(
                'INSERT INTO Sorular (soru_metni, fotograf_url, dogru_cevap_index) VALUES (?, ?, ?)',
                [soru_metni, fotograf_url || null, dogru_cevap_index]
            );
            
            const newSoruId = result.insertId;

            for (let i = 0; i < cevap_siklari.length; i++) {
                const sik_metni = cevap_siklari[i];
                const sik_index = i + 1;

                await connection.execute(
                    'INSERT INTO CevapSiklari (soru_id, sik_metni, sik_index) VALUES (?, ?, ?)',
                    [newSoruId, sik_metni, sik_index]
                );
            }

            await connection.commit();
            connection.release();
            res.json({ success: true, message: 'Soru ve şıklar başarıyla eklendi.', soru_id: newSoruId });

        } catch (error) {
            await connection.rollback();
            connection.release();
            throw error; 
        }

    } catch (error) {
        console.error('Soru ekleme hatası:', error);
        res.status(500).json({ success: false, message: 'Soru eklenirken bir sunucu hatası oluştu.' });
    }
});


// --- 5. SORU SİLME ROTASI (Admin Gerektirir) ---
app.delete('/api/admin/delete-question/:soru_id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') { 
        return res.status(403).json({ success: false, message: 'Yetkisiz erişim. Sadece adminler soru silebilir.' }); 
    }

    const soruId = req.params.soru_id;

    try {
        const [result] = await pool.query(
            'DELETE FROM Sorular WHERE soru_id = ?',
            [soruId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Silinecek soru bulunamadı.' });
        }

        res.json({ success: true, message: `Soru ID: ${soruId} başarıyla silindi.` });

    } catch (error) {
        console.error('Soru silme hatası:', error);
        res.status(500).json({ success: false, message: 'Soru silinirken sunucu hatası oluştu.' });
    }
});


// --- 6. QUIZ SORULARINI ÇEKME ROTASI (Tüm Kullanıcılar İçin) ---
app.get('/api/quiz/questions', async (req, res) => {
    try {
        const [questions] = await pool.query('SELECT soru_id, soru_metni, fotograf_url FROM Sorular ORDER BY RAND()');
        
        for (const question of questions) {
            const [choices] = await pool.query(
                'SELECT sik_index, sik_metni FROM CevapSiklari WHERE soru_id = ? ORDER BY sik_index',
                [question.soru_id]
            );
            question.siklar = choices;
        }

        res.json({ success: true, questions: questions });
    } catch (error) {
        console.error('Soru çekme hatası:', error);
        res.status(500).json({ success: false, message: 'Sorular yüklenemedi.' });
    }
});


// --- 7. QUIZ SONUÇLARINI KAYDETME ROTASI (Giriş Yapmış Kullanıcılar İçin) ---
// ** GÜNCELLENDİ: sure_saniye eklendi **
app.post('/api/quiz/submit', authenticateToken, async (req, res) => {
    const kullanici_id = req.user.kullanici_id; 
    // sure_saniye eklendi
    const { dogru_sayisi, yanlis_sayisi, sure_saniye } = req.body; 

    if (dogru_sayisi === undefined || yanlis_sayisi === undefined || sure_saniye === undefined) {
        return res.status(400).json({ success: false, message: 'Doğru, yanlış sayısı ve süre gereklidir.' });
    }

    try {
        const [result] = await pool.query(
            'INSERT INTO QuizSonuclari (kullanici_id, dogru_sayisi, yanlis_sayisi, sure_saniye) VALUES (?, ?, ?, ?)',
            [kullanici_id, dogru_sayisi, yanlis_sayisi, sure_saniye] // sure_saniye eklendi
        );

        res.json({ success: true, message: 'Quiz sonuçları başarıyla kaydedildi.', sonuc_id: result.insertId });

    } catch (error) {
        console.error('Sonuç kaydetme hatası:', error);
        res.status(500).json({ success: false, message: 'Sunucu hatası.' });
    }
});


// --- 8. ADMIN SONUÇLARI GÖRÜNTÜLEME ROTASI ---
app.get('/api/admin/results', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ success: false, message: 'Yetkisiz erişim. Sadece adminler sonuçları görebilir.' });
    }

    try {
        // sure_saniye eklendi
        const [results] = await pool.query(`
            SELECT 
                QS.sonuc_id, 
                U.email, 
                QS.dogru_sayisi, 
                QS.yanlis_sayisi, 
                QS.tarih,
                QS.sure_saniye
            FROM QuizSonuclari AS QS
            JOIN Kullanicilar AS U ON QS.kullanici_id = U.kullanici_id
            ORDER BY QS.tarih DESC
        `);

        res.json({ success: true, results: results });

    } catch (error) {
        console.error('Sonuçları çekme hatası:', error);
        res.status(500).json({ success: false, message: 'Sonuçlar yüklenirken sunucu hatası oluştu.' });
    }
});


// --- 9. LEADERBOARD ROTASI (Admin Gerektirir) ---
// ** GÜNCELLENDİ: En İyi Skorlar ve Sıralama Mantığı **
app.get('/api/admin/leaderboard', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') {
        return res.status(403).json({ success: false, message: 'Yetkisiz erişim.' });
    }

    try {
        const [leaderboard] = await pool.query(`
            SELECT 
                U.email, 
                QS.dogru_sayisi,
                (QS.dogru_sayisi + QS.yanlis_sayisi) AS toplam_soru,
                QS.sure_saniye
            FROM QuizSonuclari AS QS
            JOIN Kullanicilar AS U ON QS.kullanici_id = U.kullanici_id
            -- Sıralama: 1) Doğru sayısı (en yüksekten), 2) Süre (en düşükten)
            ORDER BY QS.dogru_sayisi DESC, QS.sure_saniye ASC, QS.tarih DESC
            LIMIT 50 
        `);

        res.json({ success: true, leaderboard: leaderboard });

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
async function startServer() {
    await initializeDatabase();
    app.listen(port, () => {
        console.log(`🚀 Sunucu şu adreste çalışıyor: http://localhost:${port}`);
    });
}

startServer();