/**
 * SessionController
 *
 * @description :: Server-side logic for managing sessions
 * @help        :: See http://links.sailsjs.org/docs/controllers
 */

module.exports = {
	new:function(req,res,next){

		res.view('session/new')
	},

	create:function(req, res, next){

		if (!req.param('email') || !req.param('password')) {
			var usernamePasswordRequiredError = [{name:'usernamePasswordRequired',message:'You must enter both a username and password'}];

			req.session.flash = {
				err:usernamePasswordRequiredError
			}

			res.redirect('/session/new');
			return;
		};

		// try to find the user by there email address
		// findOneByEmail() is a dinamic finder in that it searches the model by a particular attribute
		User.findOneByEmail(req.param('email')).exec(function(err, user){
			if (err) {return next(err)};

			// if no user is found.
			if (!user) {
				var noAccountError = [{name:'noAccount',message:' The email address ' + 'not found.' }]
				req.session.flash ={
					err:noAccountError
				}
				res.redirect('/session/new');
				return;
			};
			bcrypt = require('bcrypt');
			// compare password from the form params to the encrypted password of the user found.
			bcrypt.compare(req.param('password'), user.encryptedPassword,function(err, valid){
				if (err) { return next(err)};

				// if the password form the form doesnt match the password form the database
				if (!valid) {
					var usernamePasswordMismatchError = [{name:'usernamePasswordMismatch',message:'Invalid email and password combination'}]
					req.session.flash = {
						err: usernamePasswordMismatchError
					}
					res.redirect('/session/new');
					return;
				};
			})
			// log user in
			req.session.authenticated = true;
			req.session.user = user

			// redirect to their profile
			res.redirect('/user/show/' + user.id);
		})

	}

};

