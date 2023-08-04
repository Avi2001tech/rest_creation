const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');

const app = express();
const port = 3000; // You can change this to any desired port number


app.use(bodyParser.json());


const db = new sqlite3.Database('database.db');

db.run(`
  CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    phoneNumber TEXT NOT NULL UNIQUE
  );
`);

db.run(`
  CREATE TABLE IF NOT EXISTS spam_numbers (
    id INTEGER PRIMARY KEY,
    phoneNumber TEXT NOT NULL UNIQUE
  );
`);



app.post('/contacts', (req, res) => {
  const { name, email, phoneNumber } = req.body;

  if (!name || !email || !phoneNumber) {
    return res.status(400).json({ error: 'Name, email, and phone number are required.' });
  }

  const insertQuery = `
    INSERT INTO contacts (name, email, phoneNumber)
    VALUES (?, ?, ?);
  `;

  db.run(insertQuery, [name, email, phoneNumber], function (err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to add the contact.' });
    }

    res.json({ id: this.lastID, name, email, phoneNumber });
  });
});


app.get('/contacts', (req, res) => {
    const selectQuery = `
      SELECT c.id, c.name, c.email, c.phoneNumber, s.id AS spamId
      FROM contacts AS c
      LEFT JOIN spam_numbers AS s ON c.phoneNumber = s.phoneNumber;
    `;
  
    db.all(selectQuery, [], (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to fetch contacts.' });
      }
  
      res.json(rows);
    });
  });

  

  app.get('/search/name/:query', (req, res) => {
    const { query } = req.params;
  
    const searchQuery = `
      SELECT c.id, c.name, c.email, c.phoneNumber, s.id AS spamId
      FROM contacts AS c
      LEFT JOIN spam_numbers AS s ON c.phoneNumber = s.phoneNumber
      WHERE c.name LIKE ? || '%'
      UNION
      SELECT c.id, c.name, c.email, c.phoneNumber, s.id AS spamId
      FROM contacts AS c
      LEFT JOIN spam_numbers AS s ON c.phoneNumber = s.phoneNumber
      WHERE c.name LIKE '%' || ? || '%'
      AND c.name NOT LIKE ? || '%';
    `;
  
    db.all(searchQuery, [query, query, query], (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to perform the search.' });
      }
  
      res.json(rows);
    });
  });
  


  app.get('/search/phone/:query', (req, res) => {
    const { query } = req.params;
  
    const searchQuery = `
      SELECT c.id, c.name, c.email, c.phoneNumber, s.id AS spamId
      FROM contacts AS c
      LEFT JOIN spam_numbers AS s ON c.phoneNumber = s.phoneNumber
      WHERE c.phoneNumber = ?;
    `;
  
    db.all(searchQuery, [query], (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to perform the search.' });
      }
  
      res.json(rows);
    });
  });

  
  app.get('/contact/:id', (req, res) => {
    const { id } = req.params;
  
    const selectQuery = `
      SELECT c.id, c.name, c.email, c.phoneNumber, s.id AS spamId
      FROM contacts AS c
      LEFT JOIN spam_numbers AS s ON c.phoneNumber = s.phoneNumber
      WHERE c.id = ?;
    `;
  
    db.get(selectQuery, [id], (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to fetch contact details.' });
      }
  
      if (!row) {
        return res.status(404).json({ error: 'Contact not found.' });
      }
  
      res.json(row);
    });
  });
  

app.post('/spam', (req, res) => {
    const { phoneNumber } = req.body;
  
    if (!phoneNumber) {
      return res.status(400).json({ error: 'Phone number is required.' });
    }
  
    
    db.get(`SELECT * FROM spam_numbers WHERE phoneNumber = ?`, [phoneNumber], (err, row) => {
      if (row) {
        return res.status(400).json({ error: 'Number is already marked as spam.' });
      }
  
      
      db.run(`INSERT INTO spam_numbers (phoneNumber) VALUES (?)`, [phoneNumber], (err) => {
        if (err) {
          return res.status(500).json({ error: 'Failed to mark the number as spam.' });
        }
  
        res.json({ message: 'Number marked as spam successfully.' });
      });
    });
  });
  

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
