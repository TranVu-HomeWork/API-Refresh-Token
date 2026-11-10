const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const authLimiter = require('../middlewares/rateLimitMiddleware');
const authMiddleware = require('../middlewares/authMiddleware');

router.post('/register', authLimiter, userController.register);
router.post('/login', authLimiter, userController.login);
router.get('/profile', authMiddleware, userController.getProfile);

module.exports = router;