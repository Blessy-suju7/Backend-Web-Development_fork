const express = require('express');
const bcrypt = require('bcryptjs');
const prisma = require('../db/prisma');
const router = express.Router();

const bcryptCost = Number(process.env.BCRYPT_COST || 12);

function getUserResponse(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: user.createdAt
  };
}

function getRequestBody(req) {
  return req.body && typeof req.body === 'object' && !Array.isArray(req.body)
    ? req.body
    : {};
}

router.post('/register', async (req, res, next) => {
  const { name, email, password } = getRequestBody(req);
  const normalizedName = typeof name === 'string' ? name.trim() : '';
  const normalizedEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';

  if (
    normalizedName.length === 0 ||
    normalizedName.length > 100 ||
    normalizedEmail.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail) ||
    typeof password !== 'string' ||
    password.length < 8 ||
    Buffer.byteLength(password, 'utf8') > 72
  ) {
    return res.status(400).json({
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Provide a name, valid email address, and password of 8 to 72 bytes.'
      }
    });
  }

  try {
    const passwordHash = await bcrypt.hash(password, bcryptCost);
    const user = await prisma.user.create({
      data: { name: normalizedName, email: normalizedEmail, passwordHash }
    });

    return res.status(201).json({ user: getUserResponse(user) });
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(409).json({
        error: { code: 'EMAIL_ALREADY_REGISTERED', message: 'An account with that email already exists.' }
      });
    }
    return next(error);
  }
});

router.post('/login', async (req, res, next) => {
  const { email, password } = getRequestBody(req);
  const normalizedEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';

  try {
    const user = normalizedEmail && typeof password === 'string'
      ? await prisma.user.findUnique({ where: { email: normalizedEmail } })
      : null;

    if (
      !user ||
      Buffer.byteLength(password, 'utf8') > 72 ||
      !(await bcrypt.compare(password, user.passwordHash))
    ) {
      return res.status(401).json({
        error: { code: 'INVALID_CREDENTIALS', message: 'Email or password is incorrect.' }
      });
    }

    return res.status(200).json({ user: getUserResponse(user) });
  } catch (error) {
    return next(error);
  }
});

module.exports = router;
