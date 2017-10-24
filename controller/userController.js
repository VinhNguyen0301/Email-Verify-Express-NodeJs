const Joi = require('joi');
const passport = require('passport');
const randomstring = require('randomstring');
const User = require('../models/user');


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


    //console.log(process.env.SENDGRID_API_KEY)
        const sgMail = require('@sendgrid/mail');
        sgMail.setApiKey(process.env.SENDGRID_API_KEY);
         // Compose email
        const html5 = `Hi there,
      <br/>
      Thank you for registering!
      <br/><br/>
      Please verify your email by typing the following token:
      <br/>
      On the following page:
      <a href="http://localhost:5000/users/verify?access_token=`+ secretToken + `">http://localhost:5000/users/verify?access_token=` + secretToken +`</a>
      <br/><br/>
      Have a pleasant day.`
        const msg = {
          to: 'nguyenvinh.fit@gmail.com',
          from: 'nguyenvinh.fit@gmail.com',
          subject: 'Email-verifications from Managela',
          text: 'Thank to use my service.I love you',
          html: html5
        };
        sgMail.send(msg);
        req.flash('success', 'Please check your email.');
      res.redirect('/users/login');

    },

    Verify_Login: async(req, res, next) => {
        console.log('ok');
        try {
            const secretToken = req.query.access_token;
        
            // Find account with matching secret token
            const user = await User.findOne({ 'secretToken': secretToken });
            if (!user) {
                req.flash('error', 'No user found.');
                res.redirect('/users/verify');
                return;
            }

            user.active = true;
            user.secretToken = secretToken;
            await user.save();

            req.flash('success', 'Thank you! Now you may login.');
            res.redirect('/users/login');
        } catch (error) {
            next(error);
        }
    }
}