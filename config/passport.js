/* global process */
// load all the things we need
var LocalStrategy    = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy  = require('passport-twitter').Strategy;
var InstagramStrategy  = require('passport-instagram').Strategy;
var GoogleStrategy   = require('passport-google-oauth').OAuth2Strategy;
var LinkedInStrategy = require('passport-linkedin').Strategy;

// load up the user model
var User       = require('../app/models/user');

// load the auth variables
var configAuth = require('./auth'); 

// used for debugging purposes to easily print out object data
var util = require('util');
  //Example: console.log(util.inspect(myObject, false, null));

module.exports = function(passport) {

    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        });
    });

    // =========================================================================
    // FACEBOOK ================================================================
    // =========================================================================
    passport.use(new FacebookStrategy({

        clientID        : configAuth.facebookAuth.clientID,
        clientSecret    : configAuth.facebookAuth.clientSecret,
        callbackURL     : configAuth.facebookAuth.callbackURL,
        profileFields   : ['id', 'name', 'email'],
        passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

    },
    function(req, token, refreshToken, profile, done) {
        // asynchronous
        process.nextTick(function() {
            req.session.poster_id = 'FB-' + profile.id
            
            // check if the user is already logged in
            if (!req.user) {

                User.findOne({ 'facebook.id' : profile.id }, function(err, user) {
                    if (err)
                        return done(err);

                    if (user) {

                        // if there is a user id already but no token (user was linked at one point and then removed)
                        if (!user.facebook.token) {
                            user.facebook.token   = token;
                            user.facebook.name    = profile.name.givenName + ' ' + profile.name.familyName;
                            user.facebook.email   = (profile.email) ? profile.emails[0].value.toLowerCase() : '';
                            user.facebook.profile = profile;

                            user.save(function(err) {
                                if (err)
                                    return done(err);

                                return done(null, user);
                            });
                        }

                        return done(null, user); // user found, return that user
                    } else {
                        // if there is no user, create them
                        var newUser            = new User();

                        newUser.facebook.id         = profile.id;
                        newUser.facebook.token      = token;
                        newUser.facebook.name       = profile.name.givenName + ' ' + profile.name.familyName;
                        newUser.facebook.email      = (profile.email) ? profile.emails[0].value.toLowerCase() : '';
                        newUser.facebook.profile    = profile;

                        newUser.save(function(err) {
                            if (err)
                                return done(err);

                            return done(null, newUser);
                        });
                    }
                });

            } else {
                // user already exists and is logged in, we have to link accounts
                var user            = req.user; // pull the user out of the session

                user.facebook.id          = profile.id;
                user.facebook.token       = token;
                user.facebook.name        = profile.name.givenName + ' ' + profile.name.familyName;
                user.facebook.email       = (profile.email) ? profile.emails[0].value.toLowerCase() : '';
                user.facebook.profile     = profile;

                user.save(function(err) {
                    if (err)
                        return done(err);

                    return done(null, user);
                });

            }
        });

    }));

    // =========================================================================
    // LinkedIn
    // =========================================================================
    passport.use(new LinkedInStrategy({
        consumerKey     : configAuth.linkedinAuth.consumerKey,
        consumerSecret  : configAuth.linkedinAuth.consumerSecret,
        callbackURL     : configAuth.linkedinAuth.callbackURL,
        scope           : [ 'r_basicprofile', 'r_emailaddress'],
    },
    function(req, token, tokenSecret, profile, done) {
        console.log("passport LinkedIn, profile: " + util.inspect(profile));
        // asynchronous
        process.nextTick(function() {
            
            req.session.poster_id = 'IN-' + profile.id

            // check if the user is already logged in
            if (!req.user) {

                User.findOne({ 'linkedin.id' : profile.id }, function(err, user) {
                    if (err)
                        return done(err);

                    if (user) {
                        // if there is a user id already but no token (user was linked at one point and then removed)
                        if (!user.linkedin.token) {
                            user.linkedin.token       = token;
                            user.linkedin.name        = profile.displayName;                    
                            user.linkedin.profile     = profile;

                            user.save(function(err) {
                                if (err)
                                    return done(err);

                                return done(null, user);
                            });
                        }

                        return done(null, user); // user found, return that user
                    } else {
                        // if there is no user, create them
                        var newUser                 = new User();

                        newUser.linkedin.id          = profile.id;
                        newUser.linkedin.token       = token;
                        newUser.linkedin.profile     = profile;

                        newUser.save(function(err) {
                            if (err)
                                return done(err);

                            return done(null, newUser);
                        });
                    }
                });

            } else {
                // user already exists and is logged in, we have to link accounts
                var user                 = req.user; // pull the user out of the session

                user.linkedin.id          = profile.id;
                user.linkedin.token       = token;
                user.linkedin.profile = profile;

                user.save(function(err) {
                    if (err)
                        return done(err);

                    return done(null, user);
                });
            }
        });
    }));

    // =========================================================================
    // TWITTER =================================================================
    // =========================================================================
    passport.use(new TwitterStrategy({

        consumerKey     : configAuth.twitterAuth.consumerKey,
        consumerSecret  : configAuth.twitterAuth.consumerSecret,
        callbackURL     : configAuth.twitterAuth.callbackURL,
        passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

    },
    function(req, token, tokenSecret, profile, done) {
        
        // asynchronous
        process.nextTick(function() {

            req.session.poster_id = 'TW-' + profile.id

            // check if the user is already logged in
            if (!req.user) {

                User.findOne({ 'twitter.id' : profile.id }, function(err, user) {
                    if (err)
                        return done(err);

                    if (user) {
                        // if there is a user id already but no token (user was linked at one point and then removed)
                        if (!user.twitter.token) {
                            user.twitter.token       = token;
                            user.twitter.username    = profile.username;
                            user.twitter.displayName = profile.displayName;
                            user.twitter.profile     = profile;

                            user.save(function(err) {
                                if (err)
                                    return done(err);

                                return done(null, user);
                            });
                        }

                        return done(null, user); // user found, return that user
                    } else {
                        // if there is no user, create them
                        var newUser                 = new User();

                        newUser.twitter.id          = profile.id;
                        newUser.twitter.token       = token;
                        newUser.twitter.username    = profile.username;
                        newUser.twitter.displayName = profile.displayName;
                        newUser.twitter.profile     = profile;

                        newUser.save(function(err) {
                            if (err)
                                return done(err);

                            return done(null, newUser);
                        });
                    }
                });

            } else {
                // user already exists and is logged in, we have to link accounts
                var user                 = req.user; // pull the user out of the session

                user.twitter.id          = profile.id;
                user.twitter.token       = token;
                user.twitter.username    = profile.username;
                user.twitter.displayName = profile.displayName;
                user.twitter.profile     = profile;

                user.save(function(err) {
                    if (err)
                        return done(err);

                    return done(null, user);
                });
            }
            
        });

    }));

    // =========================================================================
    // GOOGLE ==================================================================
    // =========================================================================
    passport.use(new GoogleStrategy({
        clientID        : configAuth.googleAuth.clientID,
        clientSecret    : configAuth.googleAuth.clientSecret,
        callbackURL     : configAuth.googleAuth.callbackURL,
        scope           : ['profile', 'email'],
        passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    },
    function(req, token, refreshToken, profile, done) {
        
        // asynchronous
        process.nextTick(function() {
            
            req.session.poster_id = 'GG-' + profile.id

            // check if the user is already logged in
            if (!req.user) {

                User.findOne({ 'google.id' : profile.id }, function(err, user) {
                    if (err)
                        return done(err);

                    if (user) {

                        // if there is a user id already but no token (user was linked at one point and then removed)
                        if (!user.google.token) {
                            user.google.token       = token;
                            user.google.name        = profile.displayName;
                            user.google.email       = (profile.emails[0].value || '').toLowerCase(); // pull the first email
                            user.google.profile     = profile;

                            user.save(function(err) {
                                if (err)
                                    return done(err);

                                return done(null, user);
                            });
                        }

                        return done(null, user);
                    } else {
                        var newUser          = new User();

                        newUser.google.id          = profile.id;
                        newUser.google.token       = token;
                        newUser.google.name        = profile.displayName;
                        newUser.google.email       = (profile.emails[0].value || '').toLowerCase(); // pull the first email
                        newUser.google.profile     = profile;

                        newUser.save(function(err) {
                            if (err)
                                return done(err);

                            return done(null, newUser);
                        });
                    }
                });

            } else {
                // user already exists and is logged in, we have to link accounts
                var user               = req.user; // pull the user out of the session

                user.google.id          = profile.id;
                user.google.token       = token;
                user.google.name        = profile.displayName;
                user.google.email       = (profile.emails[0].value || '').toLowerCase(); // pull the first email
                user.google.profile     = profile;

                user.save(function(err) {
                    if (err)
                        return done(err);

                    return done(null, user);
                });

            }

        });

    }));
    
    
    
    // =========================================================================
    // Instagram ================================================================
    // =========================================================================
    passport.use(new InstagramStrategy({
        clientID        : configAuth.instagramAuth.clientID,
        clientSecret    : configAuth.instagramAuth.clientSecret,
        callbackURL     : configAuth.instagramAuth.callbackURL,
        passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    },
    function(req, token, refreshToken, profile, done) {
        // asynchronous
        process.nextTick(function() {
            console.log('Eh: ' + profile);
            // // check if the user is already logged in
            // if (!req.user) {

            //     console.log('Not logged in: ' + profile)

            // } else {
            //     // user already exists and is logged in, we have to link accounts
            //     var user            = req.user; // pull the user out of the session

            //     console.log('User logged in')
            //     console.log(profile)
            //     console.log(user)

            // }
        });

    }));
    


};
