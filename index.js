import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());

const users = [];
const refreshTokens = [];

function generateAccessToken(user) {
  const payload = {
    id: user.id,
    email: user.email,
  };

  return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
  });
}

function generateRefreshToken(user) {
  const payload = {
    id: user.id,
    email: user.email,
  };

  return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
  });
}

// middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token missing." });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token." });
    }

    req.user = user;
    next();
  });
}

// routes
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email and password are required." });
    }

    if (users.find((user) => user.email === email)) {
      return res.status(400).json({ error: "Email already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = {
      id: users.length + 1,
      email,
      password: hashedPassword,
    };

    users.push(user);

    return res.status(201).json({ message: "User registered successfully." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Registration failed." });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email and password are required." });
    }

    const user = users.find((user) => user.email === email);

    if (!user) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    refreshTokens.push(refreshToken);

    return res
      .status(200)
      .json({ accessToken, refreshToken, message: "Login successful." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Login failed." });
  }
});

app.post("/token", async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ error: "Refresh token is required." });
    }

    if (!refreshTokens.includes(refreshToken)) {
      return res.status(401).json({ error: "Invalid refresh token." });
    }

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ error: "Invalid refresh token." });
      }

      const accessToken = generateAccessToken(user);

      return res.status(200).json({ accessToken, message: "Token refreshed." });
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Token refresh failed." });
  }
});

app.post("/logout", (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ error: "Refresh token is required." });
    }

    const index = refreshToken.indexOf(refreshToken);

    if (index > -1) refreshTokens.splice(index, 1);

    return res.status(200).json({ message: "Logout successful." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Logout failed." });
  }
});

app.get("/protected", authenticateToken, (req, res) => {
  try {
    const user = req.user;

    return res.status(200).json({ message: "Protected route accessed.", user });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Protected route failed." });
  }
});

const port = process.env.PORT || 8000;
app.listen(port, () => {
  console.log("Server is running on port: ", port);
});
