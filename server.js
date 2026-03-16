const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://username:password@cluster.mongodb.net/platinum?retryWrites=true&w=majority';

mongoose.connect(MONGODB_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB Error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String },
  country: { type: String },
  balance: { type: Number, default: 0 },
  totalInvested: { type: Number, default: 0 },
  totalWithdrawn: { type: Number, default: 0 },
  investmentMethod: { type: String, default: '' },
  isAdmin: { type: Boolean, default: false },
  status: { type: String, default: 'active' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Withdrawal Schema
const withdrawalSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  userEmail: { type: String, required: true },
  userName: { type: String, required: true },
  amount: { type: Number, required: true },
  cryptoType: { type: String, required: true },
  cryptoAddress: { type: String, required: true },
  status: { type: String, default: 'pending' }, // pending, approved, rejected
  createdAt: { type: Date, default: Date.now },
  processedAt: { type: Date },
  adminNote: { type: String }
});

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, required: true }, // deposit, withdrawal, investment, profit
  amount: { type: Number, required: true },
  method: { type: String },
  status: { type: String, default: 'completed' },
  createdAt: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

// Email Transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// JWT Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    req.userId = decoded.userId;
    req.isAdmin = decoded.isAdmin;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Admin Middleware
const adminMiddleware = async (req, res, next) => {
  if (!req.isAdmin) {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, email, password, phone, country } = req.body;
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({
      fullName,
      email,
      password: hashedPassword,
      phone,
      country,
      balance: 0
    });
    
    await user.save();
    
    // Send welcome email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Welcome to PlatinumEdgeEarnings!',
      html: `
        <h2>Welcome ${fullName}!</h2>
        <p>Your account has been created successfully.</p>
        <p>You can now log in and start investing.</p>
        <br>
        <p>Best regards,<br>PlatinumEdgeEarnings Team</p>
      `
    });
    
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    
    res.json({
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        balance: user.balance,
        isAdmin: user.isAdmin
      }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ==================== USER ROUTES ====================

// Get User Profile
app.get('/api/user/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    // Get recent transactions
    const transactions = await Transaction.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .limit(10);
    
    // Get pending withdrawals
    const pendingWithdrawals = await Withdrawal.find({ 
      userId: req.userId, 
      status: 'pending' 
    }).sort({ createdAt: -1 });
    
    res.json({
      user,
      transactions,
      pendingWithdrawals
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update Profile
app.put('/api/user/profile', authMiddleware, async (req, res) => {
  try {
    const { phone, country, investmentMethod } = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.userId,
      { phone, country, investmentMethod },
      { new: true }
    ).select('-password');
    
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ==================== WITHDRAWAL ROUTES ====================

// Create Withdrawal Request
app.post('/api/withdrawals', authMiddleware, async (req, res) => {
  try {
    const { amount, cryptoType, cryptoAddress } = req.body;
    
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    if (user.balance < amount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }
    
    const withdrawal = new Withdrawal({
      userId: req.userId,
      userEmail: user.email,
      userName: user.fullName,
      amount,
      cryptoType,
      cryptoAddress
    });
    
    await withdrawal.save();
    
    // Send email notification to admin
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: 'itranslogisticltd@email.com',
      subject: 'New Withdrawal Request - PlatinumEdgeEarnings',
      html: `
        <h2>New Withdrawal Request</h2>
        <p><strong>User:</strong> ${user.fullName} (${user.email})</p>
        <p><strong>Amount:</strong> $${amount}</p>
        <p><strong>Crypto:</strong> ${cryptoType}</p>
        <p><strong>Address:</strong> ${cryptoAddress}</p>
        <p><strong>Date:</strong> ${new Date().toLocaleString()}</p>
        <br>
        <p>Login to admin panel to approve or reject this request.</p>
      `
    });
    
    // Send confirmation to user
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Withdrawal Request Received',
      html: `
        <h2>Hello ${user.fullName},</h2>
        <p>Your withdrawal request has been received and is pending approval.</p>
        <p><strong>Amount:</strong> $${amount}</p>
        <p><strong>Crypto:</strong> ${cryptoType}</p>
        <p>We will process your request within 24-48 hours.</p>
        <br>
        <p>Best regards,<br>PlatinumEdgeEarnings Team</p>
      `
    });
    
    res.status(201).json({ message: 'Withdrawal request submitted', withdrawal });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get User Withdrawals
app.get('/api/withdrawals', authMiddleware, async (req, res) => {
  try {
    const withdrawals = await Withdrawal.find({ userId: req.userId })
      .sort({ createdAt: -1 });
    res.json(withdrawals);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ==================== ADMIN ROUTES ====================

// Get All Users (Admin)
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get User Details (Admin)
app.get('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    const transactions = await Transaction.find({ userId: req.params.id })
      .sort({ createdAt: -1 });
    
    const withdrawals = await Withdrawal.find({ userId: req.params.id })
      .sort({ createdAt: -1 });
    
    res.json({ user, transactions, withdrawals });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Update User Balance (Admin)
app.put('/api/admin/users/:id/balance', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { balance, note } = req.body;
    
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    
    const oldBalance = user.balance;
    user.balance = balance;
    await user.save();
    
    // Create transaction record
    const transaction = new Transaction({
      userId: req.params.id,
      type: 'balance_adjustment',
      amount: balance - oldBalance,
      method: note || 'Admin adjustment',
      status: 'completed'
    });
    await transaction.save();
    
    // Notify user
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Balance Updated - PlatinumEdgeEarnings',
      html: `
        <h2>Hello ${user.fullName},</h2>
        <p>Your account balance has been updated.</p>
        <p><strong>Previous Balance:</strong> $${oldBalance}</p>
        <p><strong>New Balance:</strong> $${balance}</p>
        <p><strong>Note:</strong> ${note || 'Balance adjustment'}</p>
        <br>
        <p>Best regards,<br>PlatinumEdgeEarnings Team</p>
      `
    });
    
    res.json({ message: 'Balance updated', user });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get All Withdrawals (Admin)
app.get('/api/admin/withdrawals', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { status } = req.query;
    const query = status ? { status } : {};
    
    const withdrawals = await Withdrawal.find(query)
      .sort({ createdAt: -1 });
    res.json(withdrawals);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Approve/Reject Withdrawal (Admin)
app.put('/api/admin/withdrawals/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { status, adminNote } = req.body;
    
    const withdrawal = await Withdrawal.findById(req.params.id);
    if (!withdrawal) return res.status(404).json({ message: 'Withdrawal not found' });
    
    withdrawal.status = status;
    withdrawal.adminNote = adminNote;
    withdrawal.processedAt = new Date();
    await withdrawal.save();
    
    const user = await User.findById(withdrawal.userId);
    
    if (status === 'approved' && user) {
      // Deduct from balance
      user.balance -= withdrawal.amount;
      user.totalWithdrawn += withdrawal.amount;
      await user.save();
      
      // Create transaction
      const transaction = new Transaction({
        userId: withdrawal.userId,
        type: 'withdrawal',
        amount: withdrawal.amount,
        method: withdrawal.cryptoType,
        status: 'completed'
      });
      await transaction.save();
    }
    
    // Notify user
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: withdrawal.userEmail,
      subject: `Withdrawal ${status === 'approved' ? 'Approved' : 'Rejected'} - PlatinumEdgeEarnings`,
      html: `
        <h2>Hello ${withdrawal.userName},</h2>
        <p>Your withdrawal request has been <strong>${status}</strong>.</p>
        <p><strong>Amount:</strong> $${withdrawal.amount}</p>
        <p><strong>Crypto:</strong> ${withdrawal.cryptoType}</p>
        ${adminNote ? `<p><strong>Note:</strong> ${adminNote}</p>` : ''}
        <br>
        <p>Best regards,<br>PlatinumEdgeEarnings Team</p>
      `
    });
    
    res.json({ message: `Withdrawal ${status}`, withdrawal });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get Dashboard Stats (Admin)
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalBalance = await User.aggregate([{ $group: { _id: null, total: { $sum: '$balance' } } }]);
    const pendingWithdrawals = await Withdrawal.countDocuments({ status: 'pending' });
    const totalWithdrawals = await Withdrawal.aggregate([
      { $match: { status: 'approved' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    res.json({
      totalUsers,
      totalBalance: totalBalance[0]?.total || 0,
      pendingWithdrawals,
      totalWithdrawn: totalWithdrawals[0]?.total || 0
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Create Admin User (One-time setup)
app.post('/api/setup-admin', async (req, res) => {
  try {
    const { email, password, secretKey } = req.body;
    
    // Verify secret key
    if (secretKey !== (process.env.ADMIN_SECRET || 'platinum-admin-2024')) {
      return res.status(403).json({ message: 'Invalid secret key' });
    }
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      existingUser.isAdmin = true;
      await existingUser.save();
      return res.json({ message: 'User promoted to admin' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const admin = new User({
      fullName: 'Admin',
      email,
      password: hashedPassword,
      isAdmin: true,
      balance: 0
    });
    
    await admin.save();
    
    res.json({ message: 'Admin created successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
