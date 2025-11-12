// Gerekli kütüphaneleri içe aktar
const express = require('express');
const { Pool } = require('pg'); 
const cors = require('cors'); 
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000; 

// Canlı Netlify adresini çevre değişkeninden al
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://taylorswiftquiz.netlify.app'; 

// Token oluşturmak için kullanılacak gizli anahtar
const JWT_SECRET = process.env.JWT_SECRET || 'cok_gizli_taylor_swift_anahtari'; 

// --- Middleware ---
app.use(express.json()); 
app.use(cors({
    origin: ALLOWED_ORIGIN,
    methods: ['GET', 'POST', 'DELETE']
}));

// --- 1. PostgreSQL Veritabanı Bağlantısı Ayarları ---
const dbConfig = {
    connectionString: process.env.DATABASE_URL, 
    ssl: { rejectUnauthorized: false } 
};

if (process.env.NODE_ENV !== 'production') { dbConfig.ssl = false; }

let pool = new Pool(dbConfig); 

// PostgreSQL'e özel, tablo oluşturma ve admin ekleme fonksiyonu (TÜMÜ KÜÇÜK HARF)
async function setupDatabase() {
    console.log('Checking database schema (all lowercase)...');
    const client = await pool.connect();
    try {
        const schema = `
            CREATE TABLE IF NOT EXISTS users (
                user_id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                sifre_hash VARCHAR(255) NOT NULL,
                rol VARCHAR(20) NOT NULL DEFAULT 'kullanici'
            );
            CREATE TABLE IF NOT EXISTS questions (
                question_id SERIAL PRIMARY KEY,
                question_text TEXT NOT NULL,
                image_url VARCHAR(255),
                correct_answer_index INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS answers (
                answer_id SERIAL PRIMARY KEY,
                question_id INTEGER REFERENCES questions(question_id) ON DELETE CASCADE,
                answer_text VARCHAR(255) NOT NULL,
                answer_index INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS results (
                result_id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(user_id),
                correct_count INTEGER NOT NULL,
                wrong_count INTEGER NOT NULL,
                duration_seconds INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `;
        await client.query(schema);
        console.log('✅ Database schema is ready (all lowercase).');
        
        // Admin kullanıcısını ekleme
        const adminCheck = await client.query("SELECT COUNT(*) FROM users WHERE rol = 'admin'");
        if (parseInt(adminCheck.rows[0].count) === 0) {
            await client.query("INSERT INTO users (email, sifre_hash, rol) VALUES ('admin@quiz.com', '123456', 'admin')");
            console.log('✅ Default admin user created.');
        }

    } finally {
        client.release();
    }
}

setupDatabase();


// --- Rota Fonksiyonları (TÜM SORGULAR KÜÇÜK HARFE ÇEVRİLDİ) ---

// --- 2. YENİ KULLANICI KAYIT ROTASI ---
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) { return res.status(400).json({ success: false, message: 'Email and password are required.' }); }
    try {
        const existingUsers = await pool.query('SELECT email FROM users WHERE email = $1', [email]);
        if (existingUsers.rows.length > 0) { return res.status(409).json({ success: false, message: 'This email is already in use.' }); }
        const result = await pool.query("INSERT INTO users (email, sifre_hash, rol) VALUES ($1, $2, 'kullanici') RETURNING user_id", [email, password]);
        res.status(201).json({ success: true, message: 'Registration successful! You can now log in.', userId: result.rows[0].user_id });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});


// --- 3. GİRİŞ (LOGIN) ROTASI ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const users = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = users.rows[0];
        if (!user) { return res.status(401).json({ success: false, message: 'User not found.' }); }
        if (password === user.sifre_hash) { 
            const token = jwt.sign({ kullanici_id: user.user_id, rol: user.rol, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
            return res.json({ success: true, message: 'Login successful!', token: token, rol: user.rol, email: user.email });
        } else {
            return res.status(401).json({ success: false, message: 'Incorrect password.' });
        }
    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ success: false, message: 'Server error.' });
    }
});


// --- Yetkilendirme (Auth) Middleware'i ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) { return res.status(401).json({ success: false, message: 'Please log in.' }); }
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) { return res.status(403).json({ success: false, message: 'Invalid or expired token.' }); }
        req.user = user; 
        next();
    });
};

// --- 4. SORU EKLEME ROTASI ---
app.post('/api/admin/add-question', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') { return res.status(403).json({ success: false, message: 'Unauthorized. Only admins can add questions.' }); }
    const { soru_metni, fotograf_url, cevap_siklari, dogru_cevap_index } = req.body;
    if (!soru_metni || !cevap_siklari || !dogru_cevap_index || cevap_siklari.length !== 4) { return res.status(400).json({ success: false, message: 'All fields (including 4 answers) are required.' }); }
    try {
        const client = await pool.connect();
        await client.query('BEGIN');
        try {
            const result = await client.query('INSERT INTO questions (question_text, image_url, correct_answer_index) VALUES ($1, $2, $3) RETURNING question_id', [soru_metni, fotograf_url || null, dogru_cevap_index]);
            const newSoruId = result.rows[0].question_id;
            for (let i = 0; i < cevap_siklari.length; i++) {
                await client.query('INSERT INTO answers (question_id, answer_text, answer_index) VALUES ($1, $2, $3)', [newSoruId, cevap_siklari[i], i + 1]);
            }
            await client.query('COMMIT');
            client.release();
            res.json({ success: true, message: 'Question added successfully.', soru_id: newSoruId });
        } catch (error) {
            await client.query('ROLLBACK');
            client.release();
            throw error; 
        }
    } catch (error) {
        console.error('Add question error:', error);
        res.status(500).json({ success: false, message: 'Server error while adding question.' });
    }
});


// --- 5. SORU SİLME ROTASI ---
app.delete('/api/admin/delete-question/:soru_id', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') { return res.status(403).json({ success: false, message: 'Unauthorized. Only admins can delete.' }); }
    const soruId = req.params.soru_id;
    try {
        const result = await pool.query('DELETE FROM questions WHERE question_id = $1', [soruId]);
        if (result.rowCount === 0) { return res.status(404).json({ success: false, message: 'Question not found.' }); }
        res.json({ success: true, message: `Question ID: ${soruId} deleted successfully.` });
    } catch (error) {
        console.error('Delete question error:', error);
        res.status(500).json({ success: false, message: 'Server error while deleting.' });
    }
});


// --- 6. QUIZ SORULARINI ÇEKME ROTASI ---
app.get('/api/quiz/questions', async (req, res) => {
    try {
        const questionsResult = await pool.query('SELECT question_id, question_text, image_url FROM questions ORDER BY RANDOM()');
        let questions = questionsResult.rows;
        for (const question of questions) {
            const choicesResult = await pool.query('SELECT answer_index, answer_text FROM answers WHERE question_id = $1 ORDER BY answer_index', [question.question_id]);
            question.siklar = choicesResult.rows;
        }
        res.json({ success: true, questions: questions });
    } catch (error) {
        console.error('Fetch questions error:', error);
        res.status(500).json({ success: false, message: 'Could not load questions.' });
    }
});


// --- 7. QUIZ SONUÇLARINI KAYDETME ROTASI ---
app.post('/api/quiz/submit', authenticateToken, async (req, res) => {
    const kullanici_id = req.user.user_id; // Sütun adını düzelttim
    const { dogru_sayisi, yanlis_sayisi, sure_saniye } = req.body; 
    try {
        const result = await pool.query('INSERT INTO results (user_id, correct_count, wrong_count, duration_seconds) VALUES ($1, $2, $3, $4) RETURNING result_id', [kullanici_id, dogru_sayisi, yanlis_sayisi, sure_saniye]);
        res.json({ success: true, message: 'Quiz results saved successfully.', sonuc_id: result.rows[0].result_id });
    } catch (error) {
        console.error('Submit result error:', error);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});


// --- 8. ADMIN SONUÇLARI GÖRÜNTÜLEME ROTASI ---
app.get('/api/admin/results', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') { return res.status(403).json({ success: false, message: 'Unauthorized.' }); }
    try {
        const results = await pool.query(`
            SELECT R.result_id, U.email, R.correct_count, R.wrong_count, R.created_at, R.duration_seconds
            FROM results AS R JOIN users AS U ON R.user_id = U.user_id
            ORDER BY R.created_at DESC
        `);
        res.json({ success: true, results: results.rows });
    } catch (error) {
        console.error('Fetch results error:', error);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
});


// --- 9. LEADERBOARD ROTASI ---
app.get('/api/admin/leaderboard', authenticateToken, async (req, res) => {
    if (req.user.rol !== 'admin') { return res.status(403).json({ success: false, message: 'Unauthorized.' }); }
    try {
        const leaderboard = await pool.query(`
            SELECT U.email, R.correct_count, (R.correct_count + R.wrong_count) AS total_questions, R.duration_seconds
            FROM results AS R JOIN users AS U ON R.user_id = U.user_id
            ORDER BY R.correct_count DESC, R.duration_seconds ASC, R.created_at DESC
            LIMIT 50 
        `);
        res.json({ success: true, leaderboard: leaderboard.rows });
    } catch (error) {
        console.error('Leaderboard error:', error);
        res.status(500).json({ success: false, message: 'Could not load leaderboard.' });
    }
});


// --- 10. Temel Test Rotası ---
app.get('/', (req, res) => {
    res.send('Taylor Swift Quiz Backend is running successfully! (V3 - English)');
});


// Sunucuyu başlatma
app.listen(port, () => {
    console.log(`🚀 Server is running on: https://taylor-swift-quiz-site.onrender.com`);
});