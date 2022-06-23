const passport = require("passport");
const validPassword = require("../lib/passwordUtils").validPassword;
const LocalStrategy = require("passport-local").Strategy;
const connection = require("./database");
const User = connection.models.User;

const verifyCallback = (username, password, done) => {
  User.findOne({ username: username })
    .then((user) => {
      if (!user) {
        return done(null, false);
      }

      const isValid = validPassword(password, user.hash, user.salt);

      if (isValid) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    })
    .catch((err) => {
      done(err);
    });
};

const strategy = new LocalStrategy(verifyCallback);

passport.use(strategy);

// passing user property from passport authenticate function
passport.serializeUser((user, done) => {
  console.log("serializeId", user.id);
  done(null, user.id);
});

// grab the user form session
passport.deserializeUser((userId, done) => {
  User.findById(userId)
    .then((user) => {
      // populating req.user with that user
      done(null, user);
    })
    .catch((err) => done(err));
});
