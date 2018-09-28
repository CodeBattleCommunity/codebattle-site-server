const express = require('express');
const session = require('express-session');
const expressValidator = require('express-validator');
const compression = require('compression');
const MongoStore = require('connect-mongo')(session);
const chalk = require('chalk');
const dotenv = require('dotenv'); dotenv.config();
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const passport = require('passport');
const errorHandler = require('errorhandler');
const authController = require('./controllers/auth');

require('./config/passport');


const app = express();

mongoose.connect(process.env.MONGODB_URI || '', {useNewUrlParser: true});
mongoose.connection.on('error', err => {
  console.error(err);
  console.log('%s MongoDB connection error.', chalk.red('✗'));
  process.exit();
});

// Express config
app.set('port', process.env.PORT || 8080);
app.use(function(req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
  res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type, Authorization');
  next();
});
app.use(compression());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(expressValidator());
app.use(session({
  resave: true,
  saveUninitialized: true,
  secret: process.env.SECRET_KEY,
  cookie: { maxAge: 1209600000 },
  store: new MongoStore({
    url: process.env.MONGODB_URI,
    autoReconnect: true
  })
}));
app.use(passport.initialize());
app.use(passport.session());
app.disable('x-powered-by');

if (process.env.NODE_ENV !== 'production') {
  console.log('error handler added');
  app.use(errorHandler());
} else {
  app.use((err, req, res) => {
    console.error(err);
    res.status(500).send('Server Error');
  });
}

/**
 * Express middleware
 */

app.use((req, res, next) => {
  // After successful login, redirect back to the intended page
  console.log('------- req user: ', req.user);
  console.log('------- req.path: ', req.path);
  if (req.query.callback || req.headers.referer) {
    req.session.returnTo =  req.query.callback || req.headers.referer
  }
  
  console.log('Return to: ', req.session.returnTo)
  const isAuthenticated = req.isAuthenticated();
  res.locals.isAuthenticated = isAuthenticated;
  res.locals.user = req.user;
  next();
});

app.post('/signup', passport.authenticate('jwt', { session: false }), authController.postSignUp);
app.post('/signin', passport.authenticate('jwt', { session: false }), authController.postSignIn);
app.get('/signout', passport.authenticate('jwt', { session: false }), authController.getSignOut);

/* Google */
app.get('/auth/google', passport.authenticate('google', { scope: 'profile email' }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/signin' } ), (req, res) => {
  res.setHeader('x-access-token', res.locals.user.token);
  res.setHeader('Authorization', 'Bearer ' + res.locals.user.token);
  res.redirect(req.session.returnTo || '/');
});

/* VK */
app.get('/auth/vkontakte', passport.authenticate('vkontakte',{ scope: ['status', 'email', 'friends', 'notify'] }), (req, res) => {
  console.log('function will not be called')
});

app.get('/auth/vkontakte/callback', passport.authenticate('vkontakte', { failureRedirect: '/signin' } ), (req, res) => {
  res.setHeader('x-access-token', req.session.passport.user.token);
  console.log(req.session)
  res.status(200).send({});
  res.redirect(req.session.returnTo || '/');
});

app.listen(app.get('port'), () => {
  console.log('%s App is running at http://localhost:%d', chalk.green('✓'), app.get('port'));
});

module.exports = app;
