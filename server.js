const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { body, validationResult } = require('express-validator');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
require('dotenv').config();
const path = require('path');
const SALT_ROUNDS = 10;

const app = express();


app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'supersecretkey',  // 可以換成更複雜的 key
  resave: false,
  saveUninitialized: false,
}));


// MongoDB Atlas 連接
const mongoURI = process.env.MONGO_URI

mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ MongoDB Atlas 連接成功'))
.catch((error) => console.error('❌ MongoDB 連接失敗', error));

// 建立使用者資料模型
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// 註冊 API
app.post(
  '/register',
  body('username').isLength({ min: 3 }).withMessage('使用者名稱至少要 3 個字'),
  body('password').isLength({ min: 6 }).withMessage('密碼至少要 6 個字'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    try {
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res.status(409).json({ message: '使用者名稱已存在' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({ username, password: hashedPassword });
      await newUser.save();

      res.status(201).json({ message: '註冊成功' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: '伺服器錯誤，請稍後再試' });
    }
  }
);

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: '帳號或密碼錯誤' });
    }

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true, maxAge: 3600000 });
    res.json({ message: '登入成功' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '伺服器錯誤，請稍後再試' });
  }
});

function authenticateJWT(req, res, next) {
  const token = req.cookies.token;

  if (!token) return res.status(401).json({ message: '未授權的存取，請先登入' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(403).json({ message: 'Token 無效或已過期' });
  }
}


// 受保護的 API
app.get('/dashboard', authenticateJWT, (req, res) => {
  res.send('/dashboard.html');
});

// 登出 API
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: '已成功登出' });
});

// 啟動伺服器
app.listen(PORT, () => {
  console.log(`🚀 伺服器啟動於 http://localhost:${PORT}`);
});
