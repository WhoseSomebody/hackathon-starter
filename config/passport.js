const _ = require('lodash');
const passport = require('passport');
const request = require('request');
const LocalStrategy = require('passport-local').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const VKontakteStrategy = require('passport-vkontakte').Strategy;
const TwitterStrategy = require('passport-twitter').Strategy;
const OpenIDStrategy = require('passport-openid').Strategy;
const OAuthStrategy = require('passport-oauth').OAuthStrategy;
const OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
const nodemailer = require('nodemailer');

const User = require('../models/User');

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});

/**
 * Sign in using Email and Password.
 */
passport.use(new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
    User.findOne({ email: email.toLowerCase() }, (err, user) => {
        if (err) { return done(err); }
        if (!user) {
            return done(null, false, { msg: `Email ${email} not found.` });
        }
        if (user.password) {
            user.comparePassword(password, (err, isMatch) => {
                if (err) { return done(err); }
                if (isMatch) {
                    return done(null, user);
                }
                return done(null, false, { msg: 'Invalid email or password.' });
            });
        } else {
            return done(null, false, { msg: 'The password for this email is not set yet. Use social buttons to log in.' });
        }

    });
}));

/**
 * Sign in with VK.
 */
passport.use(new VKontakteStrategy({
    clientID: process.env.VK_ID,
    clientSecret: process.env.VK_APP_SECRET,
    callbackURL: 'http://localhost:3000/auth/vk/callback',
    apiVersion: '5.62',
    profileFields: ['sex', 'bdate', 'city', 'country'],
    passReqToCallback: true
}, (req, accessToken, refreshToken, params, profile, done) => {
    console.log(params);
    let gender;
    switch (profile._json.sex) {
        case 1:
            gender = 'female';
            break;
        case (2):
            gender = 'male';
            break;
        default:
            gender = udefined;
    }
    if (req.user) {
        User.findOne({ vk: profile.id }, (err, existingUser) => {
            if (err) { return done(err); }
            if (existingUser) {
                req.flash('errors', { msg: 'There is already a Vkontakte account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
                done(err);
            } else {
                User.findById(req.user.id, (err, user) => {
                    if (err) { return done(err); }
                    user.vk = profile.id;
                    user.tokens.push({ kind: 'vk', accessToken });
                    user.email = user.email || params.email;
                    user.profile.name = user.profile.name || profile.displayName;
                    user.profile.gender = user.profile.gender || gender;
                    user.profile.bdate = user.profile.bdate || new Date( profile._json.bdate.replace( /(\d{2}).(\d{2}).(\d{4})/, "$2/$1/$3"));
                    user.profile.city = user.profile.city || profile._json.city.title;
                    user.profile.country = user.profile.country || profile._json.country.title;
                    user.save((err) => {
                        req.flash('info', { msg: 'VK account has been linked.' });
                        done(err, user);
                    });
                });
            }
        });
    } else {
        User.findOne({ vk: profile.id }, (err, existingUser) => {
            if (err) { return done(err); }
            if (existingUser) {
                return done(null, existingUser);
            } else {
                User.findOne({email: params.email}, (err, existingEmailUser) => {
                    if (err) {
                        return done(err);
                    }
                    if (existingEmailUser) {
                        req.flash('errors', {msg: 'There is already an account using this email address. Sign in to that account and link it with Google manually from Account Settings.'});
                        done(err);
                    } else {
                        const user = new User();
                        user.email = params.email != "" ? params.email : undefined;
                        user.vk = profile.id;
                        user.tokens.push({kind: 'vk', accessToken});
                        user.profile.name = profile.displayName;
                        user.profile.gender = gender;
                        user.profile.bdate = new Date(profile._json.bdate.replace(/(\d{2}).(\d{2}).(\d{4})/, "$2/$1/$3"));
                        user.profile.city = profile._json.city ? profile._json.city.title : undefined;
                        user.profile.country = profile._json.country ? profile._json.country.title : undefined;

                        user.save((err) => {
                            done(err, user);
                        });
                    }
                });
            }
        });
    }
}));

/**
 * Sign in with Facebook.
 */
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_ID,
    clientSecret: process.env.FACEBOOK_SECRET,
    callbackURL: '/auth/facebook/callback',
    profileFields: ['name', 'email', 'birthday', 'gender', 'location', 'age_range'],
    passReqToCallback: true
}, (req, accessToken, refreshToken, profile, done) => {
    if (req.user) {
        User.findOne({ facebook: profile.id }, (err, existingUser) => {
            if (err) { return done(err); }
            if (existingUser) {
                req.flash('errors', { msg: 'There is already a Facebook account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
                done(err);
            } else {
                User.findById(req.user.id, (err, user) => {
                    if (err) { return done(err); }
                    user.facebook = profile.id;
                    user.tokens.push({ kind: 'facebook', accessToken });
                    user.profile.name = user.profile.name || `${profile.name.givenName} ${profile.name.familyName}`;
                    user.profile.gender = user.profile.gender || profile._json.gender;
                    user.email = user.email || profile._json.email;
                    user.profile.bdate = user.profile.bdate || profile._json.birthday;
                    user.profile.city = user.profile.city || profile._json.location;

                    user.save((err) => {
                        req.flash('info', { msg: 'Facebook account has been linked.' });
                        done(err, user);
                    });
                });
            }
        });
    } else {
        User.findOne({ facebook: profile.id }, (err, existingUser) => {
            if (err) { return done(err); }
            if (existingUser) {
                return done(null, existingUser);
            }
            User.findOne({ email: profile._json.email }, (err, existingEmailUser) => {
                if (err) { return done(err); }
                if (existingEmailUser) {
                    existingEmailUser.facebook = profile.id;
                    existingEmailUser.tokens.push({ kind: 'facebook', accessToken });
                    existingEmailUser.email = existingEmailUser.email || profile.emails[0].value;
                    existingEmailUser.profile.name = existingEmailUser.profile.name || profile.displayName;
                    existingEmailUser.profile.gender = existingEmailUser.profile.gender || profile._json.gender;
                    existingEmailUser.save((err) => {
                        req.flash('info', { msg: 'Facebook account has been linked.' });
                        done(err, existingEmailUser);
                    });
                } else {
                    const user = new User();
                    user.email = profile._json.email;
                    user.facebook = profile.id;
                    user.tokens.push({ kind: 'facebook', accessToken });
                    user.profile.name = `${profile.name.givenName} ${profile.name.familyName}`;
                    user.profile.gender = profile._json.gender;
                    user.profile.bdate = profile._json.birthday;
                    user.profile.city = profile._json.location;

                    user.save((err) => {
                        done(err, user);
                    });
                }
            });
        });
    }
}));

// Sign in with Twitter.

passport.use(new TwitterStrategy({
    consumerKey: process.env.TWITTER_KEY,
    consumerSecret: process.env.TWITTER_SECRET,
    callbackURL: '/auth/twitter/callback',
    passReqToCallback: true
}, (req, accessToken, tokenSecret, profile, done) => {
    if (req.user) {
        User.findOne({ twitter: profile.id }, (err, existingUser) => {
            if (err) { return done(err); }
            if (existingUser) {
                req.flash('errors', { msg: 'There is already a Twitter account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
                done(err);
            } else {
                User.findById(req.user.id, (err, user) => {
                    if (err) { return done(err); }
                    user.twitter = profile.id;
                    user.tokens.push({ kind: 'twitter', accessToken, tokenSecret });
                    user.profile.name = user.profile.name || profile.displayName;
                    user.profile.location = user.profile.location || profile._json.location;
                    user.save((err) => {
                        if (err) { return done(err); }
                        req.flash('info', { msg: 'Twitter account has been linked.' });
                        done(err, user);
                    });
                });
            }
        });
    } else {
        // USER IS NOT ALLOWED TO SIGN UP via TWITTER (no e-mail provided)
        User.findOne({ twitter: profile.id }, (err, existingUser) => {
            if (err) { return done(err); }
            if (existingUser) {
                return done(null, existingUser);
            }
            const user = new User();
            user.twitter = profile.id;
            user.tokens.push({ kind: 'twitter', accessToken, tokenSecret });
            user.profile.name = profile.displayName;
            user.profile.location = profile._json.location;
            user.save((err) => {
                done(err, user);
            });
        });
    }
}));

/**
 * Sign in with Google.
 */
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_ID,
    clientSecret: process.env.GOOGLE_SECRET,
    callbackURL: '/auth/google/callback',
    passReqToCallback: true
}, (req, accessToken, refreshToken, profile, done) => {
    if (req.user) {
        User.findOne({ google: profile.id }, (err, existingUser) => {
            if (err) { return done(err); }
            if (existingUser) {
                req.flash('errors', { msg: 'There is already a Google account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
                done(err);
            } else {
                User.findById(req.user.id, (err, user) => {
                    if (err) { return done(err); }
                    user.google = profile.id;
                    user.tokens.push({ kind: 'google', accessToken });
                    user.email = user.email || profile.emails[0].value;
                    user.profile.name = user.profile.name || profile.displayName;
                    user.profile.gender = user.profile.gender || profile._json.gender;
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
                    existingEmailUser.google = profile.id;
                    existingEmailUser.tokens.push({ kind: 'google', accessToken });
                    existingEmailUser.email = existingEmailUser.email || profile.emails[0].value;
                    existingEmailUser.profile.name = existingEmailUser.profile.name || profile.displayName;
                    existingEmailUser.profile.gender = existingEmailUser.profile.gender || profile._json.gender;
                    existingEmailUser.profile.bdate = existingEmailUser.profile.bdate || profile._json.birthday;

                    existingEmailUser.save((err) => {
                        req.flash('info', { msg: 'Google account has been linked.' });
                        done(err, existingEmailUser);
                    });
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
 * Login Required middleware.
 */
exports.isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
};

/**
 * Authorization Required middleware.
 */
exports.isAuthorized = (req, res, next) => {
    const provider = req.path.split('/').slice(-1)[0];

    if (_.find(req.user.tokens, { kind: provider })) {
        next();
    } else {
        res.redirect(`/auth/${provider}`);
    }
};
