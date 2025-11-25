require('dotenv').config({ quiet: true }); // Thêm quiet: true để bớt rác log
const { Pool } = require('pg'); // <--- BẠN ĐANG THIẾU DÒNG NÀY

const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: 'redirect_v2_db', 
    password: process.env.DB_PASS || '123456', // <--- CHÚ Ý: ĐIỀN PASS CỦA BẠN VÀO ĐÂY NẾU KHÁC
    port: 5432,
    max: 50,
});

module.exports = pool;