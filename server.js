const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const cookieSession = require('cookie-session');

require('dotenv').config();

const PORT = 3000;

const config = { // to prevent this keys get leaked .env file
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    COOKIE_KEY_1: process.env.COOKIE_KEY_1,
    COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTIONS = {  // helps with oauth code flow
    callbackURL: '/auth/google/callback',  // to which endpoint google needs to send the authorization code
    clientID: config.CLIENT_ID, // which client?
    clientSecret: config.CLIENT_SECRET, 
};

function verifyCallback(accessToken, refreshToken, profile, done) { // once is verified, this function is where we could compare the users password against some value in our database(validation)
    console.log('Google profile', profile); // we can use this verifycallback to save the user in the database
    done(null, profile);  // if the credentials are valid we call done to supply passport with the user that authenticated, if its invalid we pass null to the error and profile to let passport know that the user is logged in
};

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));  // callback function when user is authenticated


// Save the session to cookie
passport.serializeUser((user, done) => { // arg -> callback when user is saved to the cookie to to be sent back to browser, done callbackfor asynconic work to serialze (look up in database)
    done(null, user.id);  // .id to bring only the google id for less size in the session, for server side sess: we could store that id and to know more we use the deserialize 
});  

// Read the session from the cookie 
passport.deserializeUser((id, done) => {   // takes in an obj and returns data that will be made available inside of express on that req.user property
    // server side s examle: User.findById(id-instead of obj-).then(user => {done(null, user)})
    done(null, id);  // null if you dont put an error, obj: returns whatever is coming from the cookie
});

const app = express();

app.use(helmet()); // for security, express middleware for securing our server, before any route so it passes through helmet before any other endpoint or route


app.use(cookieSession({
    name: 'session',   // options,
    maxAge: 24 * 60 * 60 * 1000,  // time of the session
    keys: [ config.COOKIE_KEY_1, config.COOKIE_KEY_2 ],  // list of secret values used to keep the cookies secure, for signing so that only server can decide what session contains, the verify the cookie , changing this value will invalidate all existing sessions, good idea to have at ;east to keys for rotation
}));

app.use(passport.initialize());  // security related so we put it above all after helmet, function that returns passport middleware, then set the strategy, initialize passport session, sets up the passport session, populated by two fn
app.use(passport.session());  // so passport understands our cookie session and req.user obj set by the cookie session middleware, authenticates the session thats been sent to our server, it uses the keys and validates that all is signed and sets the value of the user prop on req.user obj to contain that users identity
// will allow the deserialize user function to be called

function checkLoggedIn(req, res, next) {   // middleware to restric access to the endpoints below, reusable middleware function
    console.log('Current user is:', req.user);
    const isLoggedIn = req.isAuthenticated() && req.user; // if its not null or undefined passport valideates the session, req.isAuth() (built into passport) checks specifally that passport foun the user in the session
    if (!isLoggedIn) {
        return res.status(401).json({
            error: 'You must log in!',
        });
    }
    next();
};


app.get('/auth/google',
    passport.authenticate('google', {
        scope: ['email'],
    })
);

app.get('/auth/google/callback', 
    passport.authenticate('google', {   // google servers need to be able to call this endpoint so an authorization code can be exchanged for an access token
    failureRedirect: '/failure',  // options: what happen if we fail to auth and what if its successful, where to redirect when its wrong
    successRedirect: '/',
    session: true,  // to serialize session to the cookie, its true by default it can be ommited   
    }), 
    (req, res) => {   // some additional function
    console.log('Google called us back!');
    }
); 

app.get('/auth/logout', (req, res) => {
    req.logOut(); // will clear any logged in user session and remove req.user from the requests
    return res.redirect('/'); // Redirect homepage
});

app.get('/secret', checkLoggedIn, (req,res) => {  // we will protect it so only auth users can view it, we restrict it passing the middleware function before request handler
    return res.send('Your personal secret value is 42!'); // we can add more middleware and they run in sequence before response is send: checkLoggedIn, checkPermissions,etc
});

app.get('failure', (req, res) => {
    return res.send('Failed to log in!');
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