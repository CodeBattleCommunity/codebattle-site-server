const passport = require('passport');
const { Strategy: LocalStrategy } = require('passport-local');
const { Strategy: FacebookStrategy } = require('passport-facebook');
const { Strategy: GitHubStrategy } = require('passport-github');
const { OAuth2Strategy: GoogleStrategy } = require('passport-google-oauth');
const { Strategy: VKontakteStrategy } = require('passport-vkontakte');

const JWTStrategy = require('passport-jwt').Strategy,
      ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');

const User = require('../models/user');

// passport.serializeUser((user, done) => {
//   done(null, user.id);
// });

// passport.deserializeUser((id, done) => {
//   User.findById(id, (err, user) => {
//     done(err, user);
//   });
// });

var options = {};    
options.secretOrKey = process.env.SECRET_KEY;
options.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
options.ignoreExpiration = false;

passport.serializeUser(function(user, done) {    
  var token = jwt.sign({ id: user.id },process.env.SECRET_KEY,{ expiresIn: '300m' });
  console.log("JWT user : " + user);
  console.log("JWT token : " + token);
  done(null, { user: user, token: token} );
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});

passport.use(new JWTStrategy(options, function(payload, callback) {
  console.log('JWT: ', payload)
  User.findById(payload.id, (err, user) => {
      if (err) {
        console.log('JWT: error: ', err)
        callback(err, false);
      } else if (!user) { 
        console.log('JWT: user not found')
        callback(null, false); 
        return;
      }
      console.log('JWT: user is found')
      callback(null, user);
  });
})); 

/*
* Local Strategy
*/
passport.use(new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
  User.findOne({ email: email.toLowerCase() }, (err, user) => {
    if (err) { return done(err); }

    if (!user) {
      return done(null, false, { msg: `Email ${email} not found`});
    }

    user.comparePassword(password, (err, isMatch) => {
      if (err) { return done(err); }
      if (isMatch) {
        return done(null, user);
      }
      return done(null, false, { msg: 'Invalid email or password' });
    });
  });
}));

passport.use(new VKontakteStrategy({
  clientID:     process.env.VKONTAKTE_ID,
  clientSecret: process.env.VKONTAKTE_SECRET,
  callbackURL:  process.env.VKONTAKTE_CALLBACK
},
function(accessToken, refreshToken, params, profile, done) {
  User.findOne({ vkontakte: profile.id }, function (err, user) {
    if (err) { return done(err); }
    if (user) {
      done(err, user);
    } else {
      User.findOne({email: params.email} , (err, existingEmailUser) => {
        if (err) { return done(err); }
        if (existingEmailUser) {
          user.vkontakte = profile.id;
          user.tokens.push({ kind: 'vkontakte', accessToken });
          user.profile.name = user.profile.name || profile.displayName;
          user.profile.gender = user.profile.gender || profile.gender;
          user.profile.picture = user.profile.picture || profile.photos[0].value;
          user.save((err) => {
            done(err, user);
          });
        } else {
          const user = new User();
          user.email = params.email;
          user.vkontakte = profile.id;
          user.tokens.push({ kind: 'vkontakte', accessToken });
          user.profile.name = profile.displayName;
          user.profile.gender = profile.gender;
          user.profile.picture = profile.photos[0].value;
          user.save((err) => {
            done(err, user);
          });
        }
      })
    }
  })
}))

/*
* Google strategy
*/
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_ID,
  clientSecret: process.env.GOOGLE_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK,
  passReqToCallback: true
}, (req, accessToken, refreshToken, profile, done) => {
  if (req.user) {
    User.findOne({ google: profile.id }, (err, existingUser) => {
      if (err) { return done(err); }
      if (existingUser) {
        done(err);
      } else {
        User.findById(req.user.id, (err, user) => {
          if (err) { return done(err); }
          user.google = profile.id;
          user.tokens.push({ kind: 'google', accessToken });
          user.profile.name = user.profile.name || profile.displayName;
          user.profile.gender = user.profile.gender || profile._json.gender;
          user.profile.picture = user.profile.picture || profile._json.image.url;
          user.save((err) => {
            req.flash('info', { msg: 'Google account has been linked.' });
            done(err, user);
          });
        });
      }
    });
  } else {
    User.findOne({ google: profile.id }, (err, existingUser) => {
      if (err) { return done(err); }
      if (existingUser) {
        return done(null, existingUser);
      }
      User.findOne({ email: profile.emails[0].value }, (err, existingEmailUser) => {
        if (err) { return done(err); }
        if (existingEmailUser) {
          return done(err);
        } else {
          const user = new User();
          user.email = profile.emails[0].value;
          user.google = profile.id;
          user.tokens.push({ kind: 'google', accessToken });
          user.profile.name = profile.displayName;
          user.profile.gender = profile._json.gender;
          user.profile.picture = profile._json.image.url;
          user.save((err) => {
            done(err, user);
          });
        }
      });
    });
  }
}));

/**
 * Sign in with GitHub.
 */
passport.use('github', new GitHubStrategy({
  clientID: process.env.GITHUB_ID,
  clientSecret: process.env.GITHUB_SECRET,
  callbackURL: process.env.GITHUB_CALLBACK,
  passReqToCallback: true
}, (req, accessToken, refreshToken, profile, done) => {
  if (req.user) {
      User.findOne({github: profile.id}, (err, existingUser) => {
          if (existingUser) {
              req.flash('errors', {msg: 'There is already a GitHub account that belongs to you. Sign in with that account or delete it, then link it with your current account.'});
              done(err);
          } else {
              User.findById(req.user.id, (err, user) => {
                  if (err) {
                      return done(err);
                  }
                  user.github = profile.id;
                  user.tokens.push({kind: 'github', accessToken});
                  user.profile.name = user.profile.name || profile.displayName;
                  user.profile.picture = user.profile.picture || profile._json.avatar_url;
                  user.profile.location = user.profile.location || profile._json.location;
                  user.profile.website = user.profile.website || profile._json.blog;
                  user.save((err) => {
                      req.flash('info', {msg: 'GitHub account has been linked.'});
                      done(err, user);
                  });
              });
          }
      });
  } else {
      User.findOne({github: profile.id}, (err, existingUser) => {
          if (err) {
              return done(err);
          }
          if (existingUser) {
              return done(null, existingUser);
          }
          User.findOne({email: profile._json.email}, (err, existingEmailUser) => {
              if (err) {
                  return done(err);
              }
              if (existingEmailUser) {
                  req.flash('errors', {msg: 'There is already an account using this email address. Sign in to that account and link it with GitHub manually from Account Settings.'});
                  done(err);
              } else {
                  const user = new User();
                  user.email = profile._json.email;
                  user.github = profile.id;
                  user.tokens.push({kind: 'github', accessToken});
                  user.profile.name = profile.displayName;
                  user.profile.picture = profile._json.avatar_url;
                  user.profile.location = profile._json.location;
                  user.profile.website = profile._json.blog;
                  user.save((err) => {
                      done(err, user);
                  });
              }
          });
      });
  }
}));

/**
 * Facebook Strategy
 */
passport.use('facebook', new FacebookStrategy({
  clientID: process.env.FACEBOOK_ID,
  clientSecret: process.env.FACEBOOK_SECRET,
  callbackURL: process.env.FACEBOOK_CALLBACK,
  profileFields: ['name', 'email', 'link', 'locale', 'timezone', 'gender'],
  passReqToCallback: true
}, (req, accessToken, refreshToken, profile, done) => {
  if (req.user) {
      User.findOne({facebook: profile.id}, (err, existingUser) => {
          if (err) {
              return done(err);
          }
          if (existingUser) {
              req.flash('errors', {msg: 'There is already a Facebook account that belongs to you. Sign in with that account or delete it, then link it with your current account.'});
              done(err);
          } else {
              User.findById(req.user.id, (err, user) => {
                  if (err) {
                      return done(err);
                  }
                  user.facebook = profile.id;
                  user.tokens.push({kind: 'facebook', accessToken});
                  user.profile.name = user.profile.name || `${profile.name.givenName} ${profile.name.familyName}`;
                  user.profile.gender = user.profile.gender || profile._json.gender;
                  user.profile.picture = user.profile.picture || `https://graph.facebook.com/${profile.id}/picture?type=large`;
                  user.save((err) => {
                      req.flash('info', {msg: 'Facebook account has been linked.'});
                      done(err, user);
                  });
              });
          }
      });
  } else {
      User.findOne({facebook: profile.id}, (err, existingUser) => {
          if (err) {
              return done(err);
          }
          if (existingUser) {
              return done(null, existingUser);
          }
          User.findOne({email: profile._json.email}, (err, existingEmailUser) => {
              if (err) {
                  return done(err);
              }
              if (existingEmailUser) {
                  req.flash('errors', {msg: 'There is already an account using this email address. Sign in to that account and link it with Facebook manually from Account Settings.'});
                  done(err);
              } else {
                  const user = new User();
                  user.email = profile._json.email;
                  user.facebook = profile.id;
                  user.tokens.push({kind: 'facebook', accessToken});
                  user.profile.name = `${profile.name.givenName} ${profile.name.familyName}`;
                  user.profile.gender = profile._json.gender;
                  user.profile.picture = `https://graph.facebook.com/${profile.id}/picture?type=large`;
                  user.profile.location = (profile._json.location) ? profile._json.location.name : '';
                  user.save((err) => {
                      done(err, user);
                  });
              }
          });
      });
  }
}));
