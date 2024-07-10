
import express from 'express';
import pg from 'pg';
import upload from './upload.js';
import multer from 'multer';
import ffmpeg from 'fluent-ffmpeg';
import bcrypt from 'bcrypt';
import session from 'express-session';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import bodyParser from 'body-parser';
import flash from 'connect-flash';
import expressMessages from 'express-messages';
import fs from 'fs';
import path from 'path';
import { dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const saltRounds = 10;

ffmpeg.setFfmpegPath('/usr/bin/ffmpeg');
ffmpeg.setFfprobePath('/usr/bin/ffprobe');

const { Pool } = pg;
const app = express();
const port = 3800;

const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "EXS",
  password: "varun@18",
  port: 5432,
});
pool.connect();



app.use(session({ secret: 'mahendrabahubali', resave: true, saveUninitialized: true }));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());



app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');



app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use((req, res, next) => {
  res.locals.messages = expressMessages(req, res);
  next();
});




passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      const userQuery = 'SELECT * FROM user_account WHERE email = $1';
      const userResult = await pool.query(userQuery, [email]);

      if (userResult.rows.length === 0) {
        return done(null, false, { message: 'Incorrect email.' });
      }

      const user = userResult.rows[0];
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        return done(null, false, { message: 'Incorrect password.' });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
));



passport.serializeUser((user, done) => {
  done(null, { id: user.id, userType: 'user' });
});

passport.deserializeUser(async (userData, done) => {
  try {
    const { id, userType } = userData;

    console.log('Deserializing user:', id);

    if (userType === 'user') {
      const userQuery = 'SELECT * FROM user_account WHERE id = $1';
      const userResult = await pool.query(userQuery, [id]);

      if (userResult.rows.length === 0) {
        return done(null, false);
      }

      const user = userResult.rows[0];
      return done(null, user);
    } else if (userType === 'admin') {
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
    console.error('Error during deserialization:', error);
    return done(error);
  }
});

passport.use('admin', new LocalStrategy(
  { usernameField: 'username' },
  async (username, password, done) => {
    try {
      console.log('Attempting admin login:', username, password);
      const adminQuery = 'SELECT * FROM user_account WHERE username = $1';
      const adminResult = await pool.query(adminQuery, [username]);

      if (adminResult.rows.length === 0) {
        console.log('Admin not found');
        return done(null, false, { message: 'Incorrect username.' });
      }

      const admin = adminResult.rows[0];
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




passport.serializeUser((admin, done) => {
  console.log('Serializing admin:', admin.id);
  done(null, { id: admin.id, userType: 'admin' });
});

passport.deserializeUser(async (adminData, done) => {
  try {
    const { id, userType } = adminData;

    console.log('Deserializing admin:', id);

    if (userType === 'admin') {
      const adminQuery = 'SELECT * FROM Admin WHERE id = $1';
      const adminResult = await pool.query(adminQuery, [id]);

      if (adminResult.rows.length === 0) {
        return done(null, false);
      }

      const admin = adminResult.rows[0];
      return done(null, admin);
    } else if (userType === 'user') {
      const userQuery = 'SELECT * FROM user_account WHERE id = $1';
      const userResult = await pool.query(userQuery, [id]);

      if (userResult.rows.length === 0) {
        return done(null, false);
      }

      const user = userResult.rows[0];
      return done(null, user);
    } else {
      return done(null, false);
    }
  } catch (error) {
    console.error('Error during admin deserialization:', error);
    return done(error);
  }
});


const isAdmin = (req, res, next) => {
  console.log('isAdmin middleware - req.isAuthenticated():', req.isAuthenticated());
  console.log('isAdmin middleware - req.user:', req.user);

  if (req.isAuthenticated() && req.user && req.user.usertype === 'admin') {
    return next();
  }

  console.log('isAdmin middleware - Access Forbidden');
  res.status(403).json({ error: 'Access Forbidden' });
};



const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
};

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  try {
    const { username, name, email, password, age } = req.body;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const currentDate = new Date().toISOString();
    const User = 'user';
    const insertUserQuery = 'INSERT INTO user_account (username, name, email, password, age, date_of_creation, usertype) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *';

    const userResult = await pool.query(insertUserQuery, [username, name, email, hashedPassword, age, currentDate, User]);
    const user = userResult.rows[0];

    req.login(user, (loginErr) => {
      if (loginErr) {
        console.error('Error logging in after registration:', loginErr);
        return res.status(500).send('Internal Server Error');
      }
      res.redirect('/');
    });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/login', (req, res) => {
  res.render('login', { user: req.user, message: req.flash('error') });
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true,
}));

app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      console.error('Error during authentication:', err);
      return next(err);
    }
    if (!user) {
      console.error('Authentication failed:', info.message);
      req.flash('error', info.message);
      return res.redirect('/login');
    }

    req.login(user, (loginErr) => {
      if (loginErr) {
        console.error('Error logging in after authentication:', loginErr);
        return next(loginErr);
      }
      return res.redirect('/');
    });
  })(req, res, next);
});

const redirectToHomeIfNotAuthenticated = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/');
  }
  next();
};

const setCacheControl = (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  next();
};

app.get('/account', setCacheControl, redirectToHomeIfNotAuthenticated, (req, res) => {
  res.render('account', { user: req.user });
});

app.get('/logout', setCacheControl, (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error('Error logging out:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.redirect('/login');
  });
});


app.post('/admin/deleteById', isAdmin, async (req, res) => {
  try {
    const videoId = parseInt(req.body.videoId);

    if (isNaN(videoId)) {
      return res.status(400).json({ error: 'Invalid video ID' });
    }

    
    const videoQuery = 'SELECT * FROM Video WHERE id = $1';
    const videoResult = await pool.query(videoQuery, [videoId]);

    if (videoResult.rows.length === 0) {
      return res.status(404).json({ error: 'Video not found' });
    }

    const video = videoResult.rows[0];
    const videoFilePath = path.join(__dirname, 'uploads', video.uri);
    const thumbnailFilePath = path.join(__dirname, 'public', video.thumbnail);
    

    fs.unlinkSync(videoFilePath);

    fs.unlinkSync(thumbnailFilePath);

    const deleteVideoDetailsQuery = 'DELETE FROM VideoDetails WHERE video_id = $1';
    await pool.query(deleteVideoDetailsQuery, [videoId]);

    const deleteVideoQuery = 'DELETE FROM Video WHERE id = $1';
    await pool.query(deleteVideoQuery, [videoId]);

    res.status(200).json({ message: 'Video deleted successfully' });
  } catch (error) {
    console.error('Error deleting video by ID:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});






app.post('/upload', isAuthenticated, upload.single('videoFile'), (req, res) => {
  const { videoName, tags } = req.body;
  const uri = req.file.filename;

  const thumbnailPath = `thumbnails/${uri.replace(/\.[^/.]+$/, '')}.png`;
  ffmpeg(path.join('uploads', uri))
    .screenshots({
      count: 1,
      folder: 'public/thumbnails',
      filename: `${uri.replace(/\.[^/.]+$/, '')}.png`,
      size: '320x240',
    });

  const insertVideoQuery = 'INSERT INTO Video (video_name, uri, thumbnail, tags, categories) VALUES ($1, $2, $3, $4, $5) RETURNING *';

  const processedTags = tags.split(',').map(tag => tag.trim());
  const processedCategories = Array.isArray(req.body.categories)
    ? req.body.categories.map(category => category.replace(/[^a-zA-Z]/g, ''))
    : [];

  pool.query(insertVideoQuery, [videoName, uri, thumbnailPath, [tags], [req.body.categories]], (error, results) => {
    if (error) {
      console.error('Error inserting video details:', error);
      res.status(500).send('Internal Server Error');
    } else {
      console.log('Video details added to the database:', results.rows[0]);

      const videoId = results.rows[0].id;

      const insertVideoDetailsQuery = 'INSERT INTO VideoDetails (video_id, likes, views, dislikes) VALUES ($1, 0, 0, 0)';
      pool.query(insertVideoDetailsQuery, [videoId], (detailsError) => {
        if (detailsError) {
          console.error('Error inserting video details:', detailsError);
          res.status(500).send('Internal Server Error');
        } else {
          console.log('Video details added to the VideoDetails table.');
          res.redirect('/');
        }
      });
    }
  });
});

app.get('/', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const perPage = 30;
    const offset = (page - 1) * perPage;

    const videosQuery = `
      SELECT Video.*, COALESCE(VideoDetails.likes, 0) as likes, COALESCE(VideoDetails.views, 0) as views,COALESCE(VideoDetails.dislikes, 0) as dislikes
      FROM Video
      LEFT JOIN VideoDetails ON Video.id = VideoDetails.video_id
      ORDER BY Video.id
      LIMIT $1 OFFSET $2
    `;

    const videosResult = await pool.query(videosQuery, [perPage, offset]);
    const videos = videosResult.rows;

    const totalVideosQuery = 'SELECT COUNT(*) FROM Video';
    const totalVideosResult = await pool.query(totalVideosQuery);
    const totalVideos = parseInt(totalVideosResult.rows[0].count);
    const totalPages = Math.ceil(totalVideos / perPage);

    res.render('index', { videos, currentPage: page, totalPages });
  } catch (error) {
    console.error('Error fetching videos:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/thumbnails/:page', isAuthenticated, async (req, res) => {
  const page = parseInt(req.params.page) || 1;
  const perPage = 30;

  try {
    const offset = (page - 1) * perPage;
    const videosQuery = 'SELECT * FROM Video ORDER BY id LIMIT $1 OFFSET $2';
    const videosResult = await pool.query(videosQuery, [perPage, offset]);
    const videos = videosResult.rows;

    const totalVideosQuery = 'SELECT COUNT(*) FROM Video';
    const totalVideosResult = await pool.query(totalVideosQuery);
    const totalVideos = parseInt(totalVideosResult.rows[0].count);

    const totalPages = Math.ceil(totalVideos / perPage);

    res.render('index', { videos, currentPage: page, totalPages });
  } catch (error) {
    console.error('Error fetching paginated thumbnails:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/video/:id', isAuthenticated, async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);

    await pool.query('UPDATE VideoDetails SET views = views + 1 WHERE video_id = $1', [videoId]);

    const videoQuery = 'SELECT * FROM Video WHERE id = $1';
    const videoResult = await pool.query(videoQuery, [videoId]);
    const video = videoResult.rows[0];

    const videoDetailsQuery = 'SELECT * FROM VideoDetails WHERE video_id = $1';
    const videoDetailsResult = await pool.query(videoDetailsQuery, [videoId]);
    const videoDetails = videoDetailsResult.rows[0];

    res.render('video', { video, videoDetails });
  } catch (error) {
    console.error('Error fetching and updating video details:', error);
    res.status(500).send('Internal Server Error');
  }
});

/* app.post('/incrementLikes/:id', isAuthenticated, async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);

    await pool.query('UPDATE VideoDetails SET likes = likes + 1 WHERE video_id = $1', [videoId]);

    const videoDetailsQuery = 'SELECT likes FROM VideoDetails WHERE video_id = $1';
    const videoDetailsResult = await pool.query(videoDetailsQuery, [videoId]);
    const updatedLikes = videoDetailsResult.rows[0].likes;

    res.json({ likes: updatedLikes });
  } catch (error) {
    console.error('Error incrementing likes:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
*/


app.post('/like/:id', isAuthenticated, async (req, res) => {
  try {
    const userId = req.user.id;
    const videoId = parseInt(req.params.id);

    
    const existingLikeQuery = 'SELECT liked FROM UserInteractions WHERE user_id = $1 AND video_id = $2';
    const existingLikeResult = await pool.query(existingLikeQuery, [userId, videoId]);

    if (existingLikeResult.rows.length > 0) {
      
      const liked = existingLikeResult.rows[0].liked;
      await pool.query('UPDATE VideoDetails SET likes = CASE WHEN $1 THEN likes - 1 ELSE likes + 1 END WHERE video_id = $2', [liked, videoId]);
      await pool.query('UPDATE UserInteractions SET liked = NOT liked WHERE user_id = $1 AND video_id = $2', [userId, videoId]);

      
      const updatedLikesResult = await pool.query('SELECT likes FROM VideoDetails WHERE video_id = $1', [videoId]);
      const updatedLikes = updatedLikesResult.rows[0].likes;

      res.json({ likes: updatedLikes });
    } else {
      
      await pool.query('UPDATE VideoDetails SET likes = likes + 1 WHERE video_id = $1', [videoId]);
      await pool.query('INSERT INTO UserInteractions (user_id, video_id, liked) VALUES ($1, $2, true)', [userId, videoId]);

     
      const updatedLikesResult = await pool.query('SELECT likes FROM VideoDetails WHERE video_id = $1', [videoId]);
      const updatedLikes = updatedLikesResult.rows[0].likes;

      res.json({ likes: updatedLikes });
    }
  } catch (error) {
    console.error('Error handling like:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.post('/dislike/:id', isAuthenticated, async (req, res) => {
  try {
    const userId = req.user.id;
    const videoId = parseInt(req.params.id);

    
    const existingDislikeQuery = 'SELECT liked FROM UserInteractions WHERE user_id = $1 AND video_id = $2';
    const existingDislikeResult = await pool.query(existingDislikeQuery, [userId, videoId]);

    if (existingDislikeResult.rows.length > 0) {
      
      const liked = existingDislikeResult.rows[0].liked;
      await pool.query('UPDATE VideoDetails SET dislikes = CASE WHEN $1 THEN dislikes - 1 ELSE dislikes + 1 END WHERE video_id = $2', [liked, videoId]);
      await pool.query('UPDATE UserInteractions SET liked = NOT liked WHERE user_id = $1 AND video_id = $2', [userId, videoId]);

     
      const updatedDislikesResult = await pool.query('SELECT dislikes FROM VideoDetails WHERE video_id = $1', [videoId]);
      const updatedDislikes = updatedDislikesResult.rows[0].dislikes;

      res.json({ dislikes: updatedDislikes });
    } else {
      
      await pool.query('UPDATE VideoDetails SET dislikes = dislikes + 1 WHERE video_id = $1', [videoId]);
      await pool.query('INSERT INTO UserInteractions (user_id, video_id, liked) VALUES ($1, $2, false)', [userId, videoId]);

      
      const updatedDislikesResult = await pool.query('SELECT dislikes FROM VideoDetails WHERE video_id = $1', [videoId]);
      const updatedDislikes = updatedDislikesResult.rows[0].dislikes;

      res.json({ dislikes: updatedDislikes });
    }
  } catch (error) {
    console.error('Error handling dislike:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});





app.post('/incrementViews/:id',isAuthenticated, async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    await pool.query('UPDATE VideoDetails SET views = views + 1 WHERE video_id = $1', [videoId]);
    const updatedViews = await pool.query('SELECT views FROM VideoDetails WHERE video_id = $1', [videoId]);
    res.json({ views: updatedViews.rows[0].views });
  } catch (error) {
    console.error('Error incrementing views:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

/*app.post('/updateLikesAndDislikes/:id/:action', isAuthenticated, async (req, res) => {
  try {
    const videoId = parseInt(req.params.id);
    const action = req.params.action;

    if (action === 'like') {
      await pool.query('UPDATE VideoDetails SET likes = likes + 1 WHERE video_id = $1', [videoId]);
    } else if (action === 'dislike') {
      await pool.query('UPDATE VideoDetails SET dislikes = dislikes + 1 WHERE video_id = $1', [videoId]);
    }

    const videoDetailsQuery = 'SELECT likes, dislikes FROM VideoDetails WHERE video_id = $1';
    const videoDetailsResult = await pool.query(videoDetailsQuery, [videoId]);
    const videoDetails = videoDetailsResult.rows[0];

    res.json({ likes: videoDetails.likes, dislikes: videoDetails.dislikes });
  } catch (error) {
    console.error('Error updating likes and dislikes:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
*/

app.get('/videos', async (req, res) => {
  try {
    const tag = req.query.tag;

    const videosWithTagQuery = `
      SELECT Video.*, COALESCE(VideoDetails.likes, 0) as likes, COALESCE(VideoDetails.views, 0) as views, COALESCE(VideoDetails.dislikes, 0) as dislikes
      FROM Video
      LEFT JOIN VideoDetails ON Video.id = VideoDetails.video_id
      WHERE $1 = ANY (tags)
      ORDER BY Video.id
    `;

    const videosWithTagResult = await pool.query(videosWithTagQuery, ["#"+[tag]]);
    const videosWithTag = videosWithTagResult.rows;

    
    res.render('videosWithTag', { videos: videosWithTag, currentPage: 1, totalPages: 1, tag: encodeURIComponent(tag) });

  } catch (error) {
    console.error('Error fetching videos with tag:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.get('/videos/categories/:category', async (req, res) => {
  try {
    const category = req.params.category;
    const videosWithCategoryQuery = `
    SELECT Video.*, COALESCE(VideoDetails.likes, 0) as likes, COALESCE(VideoDetails.views, 0) as views, COALESCE(VideoDetails.dislikes, 0) as dislikes
    FROM Video
    LEFT JOIN VideoDetails ON Video.id = VideoDetails.video_id
    WHERE $1 = ANY (categories)
    ORDER BY Video.id
  `;
    const videosWithCategoryResult = await pool.query(videosWithCategoryQuery, [category]);

    const videosWithCategory = videosWithCategoryResult.rows;

    res.render('videosWithCategory', { videos: videosWithCategory, currentPage: 1, totalPages: 1, category: encodeURIComponent(category) });
  } catch (error) {
    console.error('Error fetching videos with category:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});



app.get('/videosWithCategory', async (req, res) => {
  try {
    const category = req.query.category;
    const videosWithCategoryQuery = `
    SELECT Video.*, COALESCE(VideoDetails.likes, 0) as likes, COALESCE(VideoDetails.views, 0) as views, COALESCE(VideoDetails.dislikes, 0) as dislikes
    FROM Video
    LEFT JOIN VideoDetails ON Video.id = VideoDetails.video_id
    WHERE $1 = ANY (categories)
    ORDER BY Video.id
  `;
    const videosWithCategoryResult = await pool.query(videosWithCategoryQuery, [category]);

    const videosWithCategory = videosWithCategoryResult.rows;

    res.render('videosWithCategory', { videos: videosWithCategory, currentPage: 1, totalPages: 1, category: encodeURIComponent(category) });
  } catch (error) {
    console.error('Error fetching videos with category:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});




app.get('/admin/login', (req, res) => {
  res.render('adminLogin', { message: req.flash('error') });
});

app.post('/admin/login', passport.authenticate('admin', {
  successRedirect: '/admin/dashboard',
  failureRedirect: '/admin/login',
  failureFlash: true,
}));

app.get('/admin', isAuthenticated, (req, res) => {
  res.render('admin');
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    message: err.message
  });
});

app.get('/admin/dashboard', isAdmin, (req, res) => {
  console.log('Admin user:', req.user);
  res.render('adminDashboard', { admin: req.user, message: req.flash('error') });
});


app.post('/admin/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error('Error during logout:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.redirect('/admin/login');
  });
});



app.get('/upload',isAuthenticated, (req, res) => {
  res.render('upload');
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
