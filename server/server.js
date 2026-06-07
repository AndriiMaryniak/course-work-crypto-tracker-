require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('./models/User');

const app = express();

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key_change_me';

// ✅ ВИПРАВЛЕНО ЗА ЗАВДАННЯМ
const dbURI =
  process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/cryptodb';

app.use(express.json());

// CORS
const allowedOriginRegexes = [
  /^http:\/\/localhost(:\d+)?$/,
  /^http:\/\/127\.0\.0\.1(:\d+)?$/,
  /^http:\/\/192\.168\.\d+\.\d+(:\d+)?$/,
  /^http:\/\/10\.\d+\.\d+\.\d+(:\d+)?$/,
  /^http:\/\/172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+(:\d+)?$/,
];

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);

      const ok = allowedOriginRegexes.some((re) => re.test(origin));
      if (ok) return cb(null, true);

      return cb(new Error(`CORS blocked for origin: ${origin}`));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false,
  })
);

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    server: 'crypto-tracker-backend',
    time: new Date(),
  });
});

// JWT token
function createToken(user) {
  return jwt.sign(
    { userId: user._id, email: user.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// Auth middleware
async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({
      message: 'Необхідна авторизація (немає токена).',
    });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.userId);

    if (!user) {
      return res.status(401).json({
        message: 'Користувача не знайдено.',
      });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error('Помилка authMiddleware:', err);
    return res.status(401).json({
      message: 'Невірний або прострочений токен.',
    });
  }
}

// ---------------- AUTH ----------------
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({
        message: 'Email і пароль є обовʼязковими.',
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existing = await User.findOne({ email: normalizedEmail });
    if (existing) {
      return res.status(400).json({
        message: 'Користувач з таким email вже існує.',
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await User.create({
      email: normalizedEmail,
      passwordHash,
      favorites: [],
      settings: {
        language: 'ua',
        theme: 'dark',
        currency: 'uah',
      },
    });

    const token = createToken(user);

    res.status(201).json({
      token,
      user: {
        email: user.email,
        favorites: user.favorites,
        settings: user.settings,
      },
    });
  } catch (err) {
    console.error('Помилка register:', err);
    res.status(500).json({
      message: 'Внутрішня помилка сервера.',
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({
        message: 'Email і пароль є обовʼязковими.',
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      return res.status(401).json({
        message: 'Невірний email або пароль.',
      });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({
        message: 'Невірний email або пароль.',
      });
    }

    const token = createToken(user);

    res.json({
      token,
      user: {
        email: user.email,
        favorites: user.favorites,
        settings: user.settings,
      },
    });
  } catch (err) {
    console.error('Помилка login:', err);
    res.status(500).json({
      message: 'Внутрішня помилка сервера.',
    });
  }
});

// ---------------- USER ----------------
app.get('/api/user/me', authMiddleware, (req, res) => {
  const user = req.user;

  res.json({
    email: user.email,
    favorites: user.favorites,
    settings: user.settings,
  });
});

app.put('/api/user/settings', authMiddleware, async (req, res) => {
  try {
    const { language, theme, currency } = req.body || {};
    const updates = {};

    if (language) updates['settings.language'] = language;
    if (theme) updates['settings.theme'] = theme;
    if (currency) updates['settings.currency'] = currency;

    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      { $set: updates },
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      return res.status(404).json({
        message: 'Користувача не знайдено.',
      });
    }

    res.json({
      email: updatedUser.email,
      favorites: updatedUser.favorites,
      settings: updatedUser.settings,
    });
  } catch (err) {
    console.error('Помилка settings:', err);
    res.status(500).json({
      message: 'Не вдалося оновити налаштування.',
    });
  }
});

app.put('/api/user/favorites', authMiddleware, async (req, res) => {
  try {
    const { favorites } = req.body || {};

    if (!Array.isArray(favorites)) {
      return res.status(400).json({
        message: 'favorites має бути масивом.',
      });
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      { $set: { favorites } },
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      return res.status(404).json({
        message: 'Користувача не знайдено.',
      });
    }

    res.json({
      email: updatedUser.email,
      favorites: updatedUser.favorites,
      settings: updatedUser.settings,
    });
  } catch (err) {
    console.error('Помилка favorites:', err);
    res.status(500).json({
      message: 'Не вдалося оновити обрані монети.',
    });
  }
});

// ---------------- DB + SERVER START ----------------
async function start() {
  mongoose
    .connect(dbURI)
    .then(() => {
      console.log('✅ Підключено до MongoDB');

      app.listen(PORT, '0.0.0.0', () => {
        console.log(`✅ Сервер запущено на порту ${PORT}`);
      });
    })
    .catch((err) => {
      console.error('❌ Помилка підключення до MongoDB:', err);
      process.exit(1);
    });
}

start();