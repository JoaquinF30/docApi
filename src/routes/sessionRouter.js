import { Router } from 'express';
import passport from 'passport';
import { userModel } from "../dao/models/user.model.js";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const router = Router();

router.post('/register', passport.authenticate('register', 
  { failureRedirect: '/failRegister' }), 
  async (req, res) => {
    res.redirect("/login");
  }
);

// router.get("/failRegister", (req, res) => {
//   res.send({ error: "Fallo en registro" })
// })

// router.post('/login', passport.authenticate('login', { failureRedirect: '/login' }), async (req, res) => {
//   if (!req.user) {
//     return res.status(400).send({ status: "error", message: "Invalid credentials"});
//   }

//   req.session.user = {
//     username: req.user.username,
//     email: req.user.email,
//     rol: req.user.password === "adminCod3r123" ? "admin" : "usuario",
//   };
  
//   res.redirect("/products");
// });


router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await userModel.findOne({ email });

  if (!user) {
    return res.status(401).send('Tu cuenta no existe');
  }

  if (!bcrypt.compareSync(password, user.password)) {
    return res.status(401).send('Contraseña equivocada');
  }

  const userId = user._id;
  const token = jwt.sign({ exp: Math.floor(Date.now() / 1000) - 30, userId }, 'secreto');

  res.cookie('token', token, {
      maxAge: 10000,
      httpOnly: true,
    })
    .redirect('/');
});

router.get('/github', passport.authenticate('github', { scope: ['user:email'] }));

router.get(
  '/githubcallback',
  passport.authenticate('github', { failureRedirect: '/login' }),
  (req, res) => {
    req.session.user = req.user;
    req.session.isLogged = true;
    res.redirect('/products');
  }
);

router.post('/logout', async (req, res) => {
  console.log(req.session.cookie);
  req.session.destroy(err => {
    if(!err) {
      res.redirect("/login")
    } else {
      res.send({ status: "error", body: err })
    }
  })
});

export default router;