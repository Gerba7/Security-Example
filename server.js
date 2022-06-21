const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');
const helmet = require('helmet');

require('dotenv').config();

const PORT = 3000;

const config = { // to prevent this keys get leaked .env file
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
};

const app = express();

app.use(helmet()); // for security, express middleware for securing our server, before any route so it passes through helmet before any other endpoint or route

function checkLoggedIn(req, res, next) {   // middleware to restric access to the endpoints below, reusable middleware function
    const isLoggedIn = true;
    if (!isLoggedIn) {
        return res.status(401).json({
            error: 'You must log in!',
        });
    }
    next();
};


app.get('/auth/google', (req, res) => {

});

app.get('/auth/google/callback', (req,res) => {});

app.get('/auth/logout', (req, res) => {});

app.get('/secret', checkLoggedIn, (req,res) => {  // we will protect it so only auth users can view it, we restrict it passing the middleware function before request handler
    return res.send('Your personal secret value is 42!'); // we can add more middleware and they run in sequence before response is send: checkLoggedIn, checkPermissions,etc
});

app.get('/', (req,res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

https.createServer({
    key: fs.readFileSync('key.pem'), // contains a secret used when we encrypt data // key.pem is created with openssl to encrypt data // fs.read.. to read the files before passing them as options
    cert: fs.readFileSync('cert.pem')// obj with ssl certificate which then encrypts the data being send to and from our server // cert.pem is created with openssl to decrypt data
}, app).listen(PORT, () => {   // app is the second param the request listener(express app) // see notes
    console.log(`Listening on port ${PORT}...`);
})