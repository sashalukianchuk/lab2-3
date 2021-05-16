const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const connection = require('./database');
const User = connection.models.User;
const validPassword = require('../lib/passwordUtils').validPassword;

const customFields = {
    usernameField: 'uname',
    passwordField: 'pw'
};

const verifyCallback = (username, password, done) => {

    User.findOne({ username: username })
        .then((user) => {

            if (!user) { return done(null, false) }

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

}

const localStrategy = new LocalStrategy(customFields, verifyCallback);




var GitHubStrategy = require('passport-github').Strategy;

passport.use(new GitHubStrategy({
    clientID: 'b868f41939804d2a67ae',
    clientSecret: 'da1e6ff41d46b5f74f66c2323255d8b47461d9f8',
    callbackURL: "https://api.millermaers.tk/github/callback"
},
    function (accessToken, refreshToken, profile, cb) {
            return cb(null, profile);
    }
));


passport.use(localStrategy);





//define REST proxy options based on logged in user
passport.serializeUser(function (user, done) {
    done(null, user);
});

passport.deserializeUser(function (obj, done) {
    done(null, obj);
});


// passport.serializeUser((user, done) => {
//     done(null, user.id);
// });

// passport.deserializeUser((userId, done) => {
//     User.findById(userId)
//         .then((user) => {
//             done(null, user);
//         })
//         .catch(err => done(err))
// });

