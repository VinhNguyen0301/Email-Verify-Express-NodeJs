const express = require('express');
const router = express.Router();
const Joi = require('joi');
const passport = require('passport');
const randomstring = require('randomstring');

const User = require('../models/user');
const uscontroller = require('../controller/userController');
// Validation Schema

// Authorization 

router.route('/register')
    .get(uscontroller.isNotAuthenticated, (req, res) => {
        res.render('register');
    })
    .post(uscontroller.Register_Verify);

router.route('/login')
    .get(uscontroller.isNotAuthenticated, (req, res) => {
        res.render('login');
    })
    .post(passport.authenticate('local', {
        successRedirect: '/users/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    }));

router.route('/dashboard')
    .get(uscontroller.isAuthenticated, (req, res) => {
        res.render('dashboard', {
            username: req.user.username
        });
    });

router.route('/verify')
    .get(uscontroller.isNotAuthenticated, (req, res) => {
        res.render('verify');
    })
    .post(uscontroller.Verify_Login)

router.route('/logout')
    .get(uscontroller.isAuthenticated, (req, res) => {
        req.logout();
        req.flash('success', 'Successfully logged out. Hope to see you soon!');
        res.redirect('/');
    })


module.exports = router;