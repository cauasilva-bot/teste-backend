const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcryptjs');

let dbInstance = null;

async function getDB() {
  if (dbInstance) return dbInstance;

  dbInstance = await open({
    filename: './helpdesk.sqlite',
    driver: sqlite3.Database
  });

  await dbInstance.exec('PRAGMA foreign_keys = ON;');
  await initTables(dbInstance);
  await seedDatabase(dbInstance);

  return dbInstance;
}

async function initTables(db) {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('USER', 'ADMIN')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      operator_name TEXT NOT NULL,
      contact_email TEXT NOT NULL,
      contact_phone TEXT NOT NULL,
      shift TEXT NOT NULL CHECK(shift IN ('Manhã', 'Tarde', 'Noite')),
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Aberto' CHECK(status IN ('Aberto', 'Em Andamento', 'Concluído', 'Cancelado')),
      resolution_what TEXT,
      resolution_how TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      author_name TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);
}

async function seedDatabase(db) {
  const defaultPasswordHash = await bcrypt.hash('p147258@', 10);

  const seedUsers = [
    {
      username: 'Portaria Remota',
      email: 'portaria@rsterceirizacao.com.br',
      password: defaultPasswordHash,
      role: 'USER'
    },
    {
      username: 'rogerio.junior',
      email: 'rogerio.junior@rsterceirizacao.com.br',
      password: defaultPasswordHash,
      role: 'ADMIN'
    },
    {
      username: 'matheus.sario',
      email: 'matheus.sario@rstereirizacao.com.br',
      password: defaultPasswordHash,
      role: 'ADMIN'
    },
    {
      username: 'caua.silva',
      email: 'caua.silva@rsterceirizacao.com.br',
      password: defaultPasswordHash,
      role: 'ADMIN'
    }
  ];

  for (const u of seedUsers) {
    const existing = await db.get('SELECT id FROM users WHERE email = ? OR username = ?', [u.email, u.username]);
    if (!existing) {
      await db.run(
        'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
        [u.username, u.email, u.password, u.role]
      );
    }
  }
}

module.exports = { getDB };