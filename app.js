import express from "express";
import env from "dotenv";
import { createClient } from '@supabase/supabase-js'
import bcrypt from "bcrypt";
import morgan from "morgan";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import cors from "cors";

env.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Supabase setup
const supabase = createClient(
  process.env.VITE_SUPABASE_URL,
  process.env.VITE_SUPABASE_ANON_KEY
);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';


// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Unified Login/Registration with MetaMask
app.post('/api/auth/metamask', async (req, res) => {
  try {
    const { address, signature, message } = req.body;

    if (!address || !signature || !message) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Simplified signature verification (use ethers.js in production)
    let user = await supabase
      .from('users')
      .select('*')
      .eq('wallet_address', address)
      .single()
      .then(({ data, error }) => {
        if (error && error.code !== 'PGRST116') throw error;
        return data;
      });

    if (!user) {
      // Create new user with wallet address
      const { data, error } = await supabase
        .from('users')
        .insert({ wallet_address: address })
        .select()
        .single();
      
      if (error) throw error;
      user = data;
    }

    const token = jwt.sign(
      { 
        userId: user.id, 
        walletAddress: user.wallet_address,
        email: user.email 
      },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token, userId: user.id });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

// Unified Login/Registration with Email
app.post('/api/auth/email', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    let user = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single()
      .then(({ data, error }) => {
        if (error && error.code !== 'PGRST116') throw error;
        return data;
      });

    if (user) {
      // Login existing user
      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
    } else {
      // Register new user
      const hashedPassword = await bcrypt.hash(password, 10);
      const { data, error } = await supabase
        .from('users')
        .insert({ email, password: hashedPassword })
        .select()
        .single();
      
      if (error) throw error;
      user = data;
    }

    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        walletAddress: user.wallet_address 
      },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token, userId: user.id });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Link Wallet to Existing Account
app.post('/api/auth/link-wallet', authenticateToken, async (req, res) => {
  try {
    const { address, signature, message } = req.body;
    const userId = req.user.userId;

    if (!address || !signature || !message) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check if wallet is already linked to another account
    const { data: existingWalletUser } = await supabase
      .from('users')
      .select('*')
      .eq('wallet_address', address)
      .single();

    if (existingWalletUser && existingWalletUser.id !== userId) {
      return res.status(400).json({ error: 'Wallet already linked to another account' });
    }

    const { data: user, error } = await supabase
      .from('users')
      .update({ wallet_address: address })
      .eq('id', userId)
      .select()
      .single();

    if (error) throw error;

    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        walletAddress: user.wallet_address 
      },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token, message: 'Wallet linked successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Link Email to Existing Account
app.post('/api/auth/link-email', authenticateToken, async (req, res) => {
  try {
    const { email, password } = req.body;
    const userId = req.user.userId;

    if (!email || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check if email is already linked to another account
    const { data: existingEmailUser } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (existingEmailUser && existingEmailUser.id !== userId) {
      return res.status(400).json({ error: 'Email already linked to another account' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const { data: user, error } = await supabase
      .from('users')
      .update({ email, password: hashedPassword })
      .eq('id', userId)
      .select()
      .single();

    if (error) throw error;

    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        walletAddress: user.wallet_address 
      },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token, message: 'Email linked successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});


app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const { role } = req.body;
    const userId = req.user.userId;

    const { data: user, error } = await supabase
      .from('users')
      .update({ role })
      .eq('id', userId)
      .select()
      .single();

    if (error) throw error;

    res.json(user);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});


app.get("/users", async (_, response) => {
  try {
    const { data, error } = await supabase.from("users").select();
    console.log(data);
    return response.send(data);
  } catch (error) {
    console.log(error);
    return response.send({ error });
  }
});

//get a single user
app.get("/users/:id", async (request, response) => {
  try {
    const { data, error } = await supabase
      .from("users")
      .select()
      .eq("id", request.params.id)
    console.log(data);
    return response.send(data);
  } catch (error) {
    return response.send({ error });
  }
});

//register a user
app.post("/users", async (request, response) => {
  try {
    console.log(request.body);
    const { data, error } = await supabase.from("users").insert(request.body);
    if (error) {
      return response.status(400).json(error);
    }
    response.status(200).json(request.body);
    console.log("succesfully registered")
  } catch (error) {
    console.log(error);
    response.send({ error });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});