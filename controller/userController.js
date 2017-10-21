const Joi = require('joi');
const passport = require('passport');
const randomstring = require('randomstring');
const User = require('../models/user');
const sendgrid = require('sendgrid')(process.env.U,process.env.PASSWORD);


const userSchema = Joi.object().keys({
    email: Joi.string().email().required(),
    username: Joi.string().required(),
    password: Joi.string().regex(/^[a-zA-Z0-9]{3,30}$/).required(),
    confirmationPassword: Joi.any().valid(Joi.ref('password')).required()
});



module.exports = {


    isAuthenticated: (req, res, next) => {
     if (req.isAuthenticated()) {
         return next();
     } else {
         req.flash('error', 'Sorry, but you must be registered first!');
         res.redirect('/');

     }
 },

    isNotAuthenticated: (req, res, next) => {
        if (req.isAuthenticated()) {
            req.flash('error', 'Sorry, but you are already logged in!');
            res.redirect('/');
        } else {
            return next();
        }
    },

    Register_Verify: async(req, res, next) => {
        try {
            const result = Joi.validate(req.body, userSchema);
            if (result.error) {
                req.flash('error', 'Data is not valid. Please try again.');
                res.redirect('/users/register');
                return;
            }

            // Checking if email is already taken
            const user = await User.findOne({ 'email': result.value.email });
            if (user) {
                req.flash('error', 'Email is already in use.');
                res.redirect('/users/register');
                return;
            }

            // Hash the password
            const hash = await User.hashPassword(result.value.password);

            // Generate secret token
            const secretToken = randomstring.generate();
            console.log('secretToken', secretToken);

            // Save secret token to the DB
            result.value.secretToken = secretToken;

            // Flag account as inactive
            result.value.active = false;

            // Save user to DB
            delete result.value.confirmationPassword;
            result.value.password = hash;

            const newUser = await new User(result.value);
            console.log('newUser', newUser);
            await newUser.save();

            // Compose email
            const html = `Hi there,
                    <br/>
                    Thank you for registering!
                    <br/><br/>
                    Please verify your email by typing the following token:
                    <br/>
                    Token: <b>${secretToken}</b>
                    <br/>
                    On the following page:
                    <a href="http://localhost:5000/users/verify">http://localhost:5000/users/verify</a>
                    <br/><br/>
                    Have a pleasant day.`

                sendgrid.send({
        to: process.env.EMAIL,
        from: 'noreply@gmail.com',
        subject: 'verify-email',
        text: html
    }, function(err, json) {
        if (err) { return res.send('Something went wrong'); }
       res.send('Send cmmr');
    });
            

            req.flash('success', 'Please check your email.');
            res.redirect('/users/login');
        } catch (error) {
            next(error);
        }
    },

    Verify_Login: async(req, res, next) => {
        try {
            const { secretToken } = req.body;

            // Find account with matching secret token
            const user = await User.findOne({ 'secretToken': secretToken });
            if (!user) {
                req.flash('error', 'No user found.');
                res.redirect('/users/verify');
                return;
            }

            user.active = true;
            user.secretToken = '';
            await user.save();

            req.flash('success', 'Thank you! Now you may login.');
            res.redirect('/users/login');
        } catch (error) {
            next(error);
        }
    }
}