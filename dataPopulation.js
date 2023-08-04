const sqlite3 = require('sqlite3').verbose();
const faker = require('faker');

const db = new sqlite3.Database('database.db');

// Function to generate random contacts
function generateRandomContact() {
  const name = faker.name.findName();
  const email = faker.internet.email();
  const phoneNumber = faker.phone.phoneNumberFormat();

  return { name, email, phoneNumber };
}

// Function to insert multiple random contacts into the database
function populateDatabase(numContacts) {
  for (let i = 0; i < numContacts; i++) {
    const contact = generateRandomContact();

    const insertQuery = `
      INSERT INTO contacts (name, email, phoneNumber)
      VALUES (?, ?, ?);
    `;

    db.run(insertQuery, [contact.name, contact.email, contact.phoneNumber], function (err) {
      if (err) {
        console.error('Error inserting contact:', err);
      }
    });
  }

  console.log(`${numContacts} contacts inserted into the database.`);
}

const numContactsToGenerate = 50; // Change this number to set the desired number of random contacts
populateDatabase(numContactsToGenerate);
