const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const router = express.Router();
const SECRET_KEY = "secretkey"; // Ganti dengan kunci rahasia yang lebih aman

// Konfigurasi koneksi database PostgreSQL
const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "user_tes1",
  password: "",
  port: 5432,
});

// Middleware untuk verifikasi token JWT
function verifyToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    req.userId = decoded.id;
    next();
  });
}

// Endpoint untuk signup
router.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res
        .status(400)
        .json({ message: "Username and password are required" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Simpan pengguna ke dalam database
    const query =
      "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id";
    const result = await pool.query(query, [username, hashedPassword]);
    const userId = result.rows[0].id;

    // Buat token JWT
    const token = jwt.sign({ id: userId }, SECRET_KEY, { expiresIn: "1h" });

    res.status(201).json({ message: "User created successfully", token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Endpoint untuk sign in
router.post("/signin", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res
        .status(400)
        .json({ message: "Username and password are required" });
    }

    // Ambil pengguna dari database berdasarkan username
    const query = "SELECT * FROM users WHERE username = $1";
    const result = await pool.query(query, [username]);
    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Buat token JWT
    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: "1h" });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Contoh endpoint yang membutuhkan autentikasi
router.get("/profile", verifyToken, async (req, res) => {
  try {
    const userId = req.userId;

    // Ambil data profil pengguna dari database
    const query = "SELECT * FROM users WHERE id = $1";
    const result = await pool.query(query, [userId]);
    const user = result.rows[0];

    res.json({ message: "You are authorized", user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

module.exports = router;
