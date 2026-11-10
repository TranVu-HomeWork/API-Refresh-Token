const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
  const authorizationHeader = req.headers.authorization;

  if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: {
        code: 'TOKEN_MISSING',
        message: 'Bạn chưa cung cấp Access Token.'
      }
    });
  }

  const token = authorizationHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_ACCESS_SECRET
    );

    req.user = decoded;

    return next();
  } catch (error) {
    const message = error.name === 'TokenExpiredError'
      ? 'Access Token đã hết hạn.'
      : 'Access Token không hợp lệ.';

    return res.status(401).json({
      success: false,
      error: {
        code: 'INVALID_TOKEN',
        message
      }
    });
  }
};

module.exports = authMiddleware;