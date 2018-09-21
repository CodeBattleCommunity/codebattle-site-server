const express = require('express');
const session = require('express-session');
const expressValidator = require('express-validator');
const compression = require('compression');
const MongoStore = require('connect-mongo')(session);
const chalk = require('chalk');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const passport = require('passport');
const errorHandler = require('errorhandler');
const bearerToken = require('express-bearer-token');


const authController = require('./controllers/auth');

dotenv.config();

const passportConfig = require('./config/passport');
const app = express();

mongoose.connect(process.env.MONGODB_URI || '', {useNewUrlParser: true});
mongoose.connection.on('error', err => {
  console.error(err);
  console.log('%s MongoDB connection error.', chalk.red('✗'));
  process.exit();
});

// Express config
app.set('port', process.env.PORT || 8080);
app.use(compression());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(expressValidator());
app.use(session({
  resave: true,
  saveUninitialized: true,
  secret: 'test secret',
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

app.post('/auth/signup', authController.postSignUp);
app.post('/auth/signin', authController.postSignIn);
app.get('/auth/signout', authController.getSignOut);
app.get('/auth/google', passport.authenticate('google', { scope: 'profile email' }));
app.get('/auth/google/callback', passport.authenticate('google', null), (req, res) => {
  console.log(res.body);
  return res.status(200).send('success');
});

app.listen(app.get('port'), () => {
  console.log('%s App is running at http://localhost:%d', chalk.green('✓'), app.get('port'));
});

module.exports = app;
