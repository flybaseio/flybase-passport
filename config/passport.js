// config/passport.js

// load all the things we need
var LocalStrategy   = require('passport-local').Strategy;
var bcrypt   = require('bcrypt-nodejs');

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

};
