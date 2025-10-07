#!/usr/bin/env node
/*
Автоматическое создание MongoDB
*/

require('dotenv').config();
const { MongoClient } = require('mongodb');

async function main() {
  const uri = process.env.DB_URI;
  const dbName = process.env.DB_NAME || 'notes';
  if (!uri) {
    console.error('Укажите переменную окружения DB_URI');
    process.exit(1);
  }

  const client = new MongoClient(uri);
  try {
    await client.connect();
    const db = client.db(dbName);

    // Users
    await db.collection('users').createIndex({ username: 1 }, { unique: true });

    // Sessions
    await db.collection('sessions').createIndex({ user_id: 1, createdAt: -1 });

    // Notes
    await db.collection('notes').createIndex({ user_id: 1, createdAt: -1 });
    await db.collection('notes').createIndex({ user_id: 1, archived: 1 });
    await db.collection('notes').createIndex({ user_id: 1, title: 1 });

    console.log('База данных успешно создана');
  } finally {
    await client.close();
  }
}

main().catch((err) => {
  console.error('Ошибка создания базы данных:', err);
  process.exit(1);
});
