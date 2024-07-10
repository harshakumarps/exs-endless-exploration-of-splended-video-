
import express from 'express';
import pg from 'pg';
import bcrypt from 'bcrypt';
import session from 'express-session';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import bodyParser from 'body-parser';
import flash from 'connect-flash';
import expressMessages from 'express-messages';
import { isAuthenticated } from './server.js';


const isAdmin = (req, res, next) => {
    console.log('isAdmin middleware - req.isAuthenticated():', req.isAuthenticated());
    console.log('isAdmin middleware - req.user:', req.user);
  
    if (req.isAuthenticated() && req.user && req.user.userType === 'admin') {
      return next();
    }
  
    console.log('isAdmin middleware - Access Forbidden');
    res.status(403).json({ error: 'Access Forbidden' });
  };


const initializeAdminAuth = (pool,app) => {

    

    
    passport.use('admin', new LocalStrategy(
        { usernameField: 'username' },
        async (username, password, done) => {
          try {
            console.log('Attempting admin login:', username, password);
            const adminQuery = 'SELECT * FROM Admin WHERE username = $1';
            const adminResult = await pool.query(adminQuery, [username]);
      
            if (adminResult.rows.length === 0) {
              console.log('Admin not found');
              return done(null, false, { message: 'Incorrect username.' });
            }
      
            const admin = adminResult.rows[0];

            
            passport.session.adminId = admin.id;

            const passwordMatch = await bcrypt.compare(password, admin.password);
      
            if (!passwordMatch) {
              console.log('Incorrect password');
              return done(null, false, { message: 'Incorrect password.' });
            }
      
            console.log('Admin login successful');
            return done(null, admin);
          } catch (error) {
            console.log('Error during admin authentication:', error);
            return done(error);
          }
        }
      ));

      
      const adminSession = session({
        name: 'admin-session',
        secret: 'mahendrabahubali',
        resave: false,
        saveUninitialized: false,
        genid: (req) => {
            
            return passport.session.adminId = admin.id || uuid(); 
        },
    });
    
    app.use('/admin', adminSession);
    app.use(passport.initialize());
app.use(passport.session());

      
  
    
    passport.serializeUser((admin, done) => {
        done(null, { id: admin.id, userType: 'admin' });
    });
  
  passport.deserializeUser(async (adminData, done) => {
    try {
      const { id, userType } = adminData;
  
      if (userType === 'admin') {
        const adminQuery = 'SELECT * FROM Admin WHERE id = $1';
        const adminResult = await pool.query(adminQuery, [id]);
  
        if (adminResult.rows.length === 0) {
          return done(null, false);
        }
  
        const admin = adminResult.rows[0];
        return done(null, admin);
      } else {
        return done(null, false);
      }
    } catch (error) {
      return done(error);
    }
  });
  
    
    
  };
  
  const adminRoutes = (app) => {
    app.get('/admin', isAuthenticated, (req, res) => {
      res.render('admin');
    });
  
    app.get('/admin/dashboard', isAdmin, (req, res) => {
      console.log('Admin user:', req.user);
      res.render('adminDashboard', { admin: req.user });
    });
  
    app.get('/admin/login', (req, res) => {
      res.render('adminLogin', { message: req.flash('error') });
    });
  
    app.post('/admin/login', passport.authenticate('admin', {
      successRedirect: '/admin/dashboard',
      failureRedirect: '/admin/login',
      failureFlash: true,
    }));
  };
  
  export { initializeAdminAuth, adminRoutes };
  