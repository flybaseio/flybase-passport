// config/passport.js

// load all the things we need
var LocalStrategy   = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy  = require('passport-twitter').Strategy;
var GoogleStrategy  = require('passport-google-oauth').OAuth2Strategy;
var bcrypt   = require('bcrypt-nodejs');

// load the auth variables
var configAuth = require('./auth'); // use this one for testing

function generateHash(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
}
function validPassword(password, hash) {
    return bcrypt.compareSync(password, hash);
}

// expose this function to our app using module.exports
module.exports = function(usersRef, passport) {

    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        done(null, user._id);
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        usersRef.where({"_id": id}).limit(1).on('value').then( function( rec ){
            var user = rec.first().value();
            done(null, user);
        },function(err){
            done(err, null);
        });
    });

     // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use('local-signup', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, email, password, done) {

        // find a user whose email is the same as the forms email
        // we are checking to see if the user trying to login already exists
        usersRef.where({"local.email": email}).limit(1).on('value').then( function( rec ){
            done(null, false, req.flash('signupMessage', 'That email is already taken.'));
        },function(err){
            var newUser = {};
            newUser.local = {};
            newUser.local.email    = email;
            newUser.local.password = generateHash(password); // use the generateHash function in our user model
            // save the user
            usersRef.push(newUser, function(resp) {
                var user = resp.first().value();
                done(null, user);
            });
        });
    }));

    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================
    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use('local-login', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, email, password, done) { // callback with email and password from our form

        // find a user whose email is the same as the forms email
        // we are checking to see if the user trying to login already exists
        usersRef.where({"local.email": email}).limit(1).on('value').then( function( rec ){
            var user = rec.first().value();
            if (!validPassword(password, user.local.password) ){
                done(null, false, req.flash('loginMessage', 'Oops! Wrong password.')); // create the loginMessage and save it to session as flashdata
            }

            // all is well, return successful user
            return done(null, user);
        },function(err){
            done(null, false, req.flash('loginMessage', 'No user found.')); // req.flash is the way to set flashdata using connect-flash
        });
    }));

    // =========================================================================
     // FACEBOOK ================================================================
     // =========================================================================
     passport.use(new FacebookStrategy({
         clientID        : configAuth.facebookAuth.clientID,
         clientSecret    : configAuth.facebookAuth.clientSecret,
         callbackURL     : configAuth.facebookAuth.callbackURL,
         passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
     },
     function(req, token, refreshToken, profile, done) {
         // asynchronous
         process.nextTick(function() {
             // check if the user is already logged in
             if (!req.user) {
				 usersRef.where({ 'facebook.id' : profile.id }).limit(1).on('value').then( function( rec ){
		             var user = rec.first().value();
                     if (user) {
                         // if there is a user id already but no token (user was linked at one point and then removed)
                         if (!user.facebook.token) {
                             user.facebook.token = token;
                             user.facebook.name  = profile.name.givenName + ' ' + profile.name.familyName;
                             user.facebook.email = profile.emails[0].value;
							 usersRef.push(user, function(resp) {
				                 var user = resp.first().value();
				                 done(null, user);
				             });
                         }

                         return done(null, user); // user found, return that user
                     } else {
                         // if there is no user, create them
                         var newUser            = {};
                         newUser.facebook.id    = profile.id;
                         newUser.facebook.token = token;
                         newUser.facebook.name  = profile.name.givenName + ' ' + profile.name.familyName;
                         newUser.facebook.email = profile.emails[0].value;

						 usersRef.push(newUser, function(resp) {
							 var user = resp.first().value();
							 done(null, user);
						 });
                     }
                 });

             } else {
                 // user already exists and is logged in, we have to link accounts
                 var user            = req.user; // pull the user out of the session

                 user.facebook.id    = profile.id;
                 user.facebook.token = token;
                 user.facebook.name  = profile.name.givenName + ' ' + profile.name.familyName;
                 user.facebook.email = profile.emails[0].value;
				 usersRef.push(newUser, function(resp) {
					var user = resp.first().value();
					done(null, user);
				 });
             }
         });

     }));
/*
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

                             user.save(function(err) {
                                 if (err)
                                     throw err;
                                 return done(null, user);
                             });
                         }

                         return done(null, user); // user found, return that user
                     } else {
                         // if there is no user, create them
                         var newUser                 = {};

                         newUser.twitter.id          = profile.id;
                         newUser.twitter.token       = token;
                         newUser.twitter.username    = profile.username;
                         newUser.twitter.displayName = profile.displayName;

                         newUser.save(function(err) {
                             if (err)
                                 throw err;
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

                 user.save(function(err) {
                     if (err)
                         throw err;
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
         passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

     },
     function(req, token, refreshToken, profile, done) {

         // asynchronous
         process.nextTick(function() {

             // check if the user is already logged in
             if (!req.user) {

                 User.findOne({ 'google.id' : profile.id }, function(err, user) {
                     if (err)
                         return done(err);

                     if (user) {

                         // if there is a user id already but no token (user was linked at one point and then removed)
                         if (!user.google.token) {
                             user.google.token = token;
                             user.google.name  = profile.displayName;
                             user.google.email = profile.emails[0].value; // pull the first email

                             user.save(function(err) {
                                 if (err)
                                     throw err;
                                 return done(null, user);
                             });
                         }

                         return done(null, user);
                     } else {
                         var newUser          = {};

                         newUser.google.id    = profile.id;
                         newUser.google.token = token;
                         newUser.google.name  = profile.displayName;
                         newUser.google.email = profile.emails[0].value; // pull the first email

                         newUser.save(function(err) {
                             if (err)
                                 throw err;
                             return done(null, newUser);
                         });
                     }
                 });

             } else {
                 // user already exists and is logged in, we have to link accounts
                 var user               = req.user; // pull the user out of the session

                 user.google.id    = profile.id;
                 user.google.token = token;
                 user.google.name  = profile.displayName;
                 user.google.email = profile.emails[0].value; // pull the first email

                 user.save(function(err) {
                     if (err)
                         throw err;
                     return done(null, user);
                 });

             }

         });

     }));
*/
};
