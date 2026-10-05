const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { getDB } = require('./database');

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_helpdesk_key_2026';

// Autenticação Híbrida: Login por E-mail OU Username no mesmo campo (loginIdentifier)
async function login(loginIdentifier, password) {
  if (!loginIdentifier || !password) {
    throw { status: 400, message: 'Identificador (E-mail/Username) e senha são obrigatórios.' };
  }

  const db = await getDB();
  const user = await db.get(
    'SELECT * FROM users WHERE LOWER(email) = LOWER(?) OR LOWER(username) = LOWER(?)',
    [loginIdentifier.trim(), loginIdentifier.trim()]
  );

  if (!user) {
    throw { status: 401, message: 'Credenciais inválidas.' };
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    throw { status: 401, message: 'Credenciais inválidas.' };
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '8h' }
  );

  return {
    token,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    }
  };
}

// Middleware para verificação do Token JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido ou expirado.' });
    }
    req.user = decoded;
    next();
  });
}

// Middleware de autorização para Admins
function requireAdmin(req, res, next) {
  if (req.user && req.user.role === 'ADMIN') {
    next();
  } else {
    return res.status(403).json({ error: 'Acesso restrito a administradores.' });
  }
}

// Bloqueio RBAC estrito para alteração de senha
async function changePassword(requestorUser, targetUserId, newPassword) {
  if (!newPassword || newPassword.trim().length < 6) {
    throw { status: 400, message: 'A nova senha deve possuir no mínimo 6 caracteres.' };
  }

  // Regra de Negócio RBAC: Perfil USER tem bloqueio absoluto para alterar a própria senha
  if (requestorUser.role === 'USER') {
    throw { status: 403, message: 'Acesso negado: Usuários do perfil USER não têm permissão para alterar senhas.' };
  }

  // Perfil ADMIN pode alterar a própria senha ou de outros usuários
  if (requestorUser.role === 'ADMIN') {
    const db = await getDB();
    const targetUser = await db.get('SELECT id FROM users WHERE id = ?', [targetUserId]);

    if (!targetUser) {
      throw { status: 404, message: 'Usuário de destino não encontrado.' };
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, targetUserId]);

    return { message: 'Senha atualizada com sucesso.' };
  }

  throw { status: 403, message: 'Permissão insuficiente.' };
}

module.exports = {
  login,
  authenticateToken,
  requireAdmin,
  changePassword
};