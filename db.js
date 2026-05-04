const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const path = require('path');
const fs = require('fs');

const DB_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

const adapter = new FileSync(path.join(DB_DIR, 'db.json'));
const db = low(adapter);

db.defaults({
  applications: [],
  users: [],
  students: [],
  notifications: [],      // broadcast messages
  attachments: [],        // files attached to notifications
  counters: { appSeq: 1000, notifSeq: 0 }
}).write();

module.exports = db;
