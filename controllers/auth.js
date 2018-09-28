const { check } = require('express-validator/check');
const passport = require('passport');
const User = require('../models/user');

exports.postSignUp = (req, res, next) => {
  // TODO: those req.assert methods are deprecated please them to new version
  // https://express-validator.github.io/docs/check-api.html
  req.checkBody('email', 'Email is not valid').isEmail();
  req.checkBody('password', 'Password must be at least 4 characters').len(4);
  req.sanitize('email').normalizeEmail({ gmail_remove_dots: false});

  const errors = req.validationErrors();
  console.log(req.body);

  if (errors) {
    // TODO: create a common error handler
    return res.status(404).send('Email or password is not valid');
  }

  const user = new User({
    email: req.body.email,
    password: req.body.password
  });

  User.findOne({ email: req.body.email }, (err, existingUser) => {
    if (err) { return res.status(404).send(err); }

    if (existingUser) {
      return res.status(404).send('User already exists');
    }

    user.save(err => {
      if (err) { return res.status(500).send(err) ;}

      return res.status(200).end('Success');
    });

  });
};

exports.postSignIn = (req, res, next) => {
  req.assert('email', 'Email is not valid').isEmail();
  req.assert('password', 'Password cannot be blank').notEmpty();
  req.sanitize('email').normalizeEmail({ gmail_remove_dots: false});

  const errors = req.validationErrors();

  if (errors) {
    // TODO: create a common error handler
    return res.status(404).send('Email or password is not valid');
  }

  passport.authenticate('local', (err, user, info) => {
    if (err) { return res.status(404).send(err); }

    if (!user) {
      return res.status(404).send(info);
    }

    req.logIn(user, err => {
      if (err) { return res.status(404).send(err); }
      return res.status(200).send('Success');
    });
  })(req, res, next);
};

exports.getSignOut = (req, res, next) => {
  req.logout();
  req.session.destroy(err => {
    if (err) { console.error('Failed to destroy user session', err); }
    res.status(200).send('Success');
    req.user = null;
  });
};

/**
 * Login Required middleware.
 */
exports.isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
      return next();
  }
  res.status(400)
};

/**
* Authorization Required middleware.
*/
exports.isAuthorized = (req, res, next) => {
  const provider = req.path.split('/').slice(-1)[0];
  const token = req.user.tokens.find(token => token.kind === provider);
  if (token) {
      next();
  } else {
      res.redirect(`/auth/${provider}`);
  }
};


const eventRegistration = () => {};
