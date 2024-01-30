import { Router } from 'express';
import passport from 'passport';
import { userModel } from "../dao/models/user.model.js";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const router = Router();

router.post('/register', passport.authenticate('register', 
  { 
    successRedirect: "/products", 
    failureRedirect: "/failRegister",
  }),
);

router.get("/failRegister", (req, res) => {
  res.send({ error: "Fallo en registro" })
})

// router.post('/login', async (req, res) => {
//   const { email, password, username } = req.body;
//   const user = await userModel.findOne({ email });

//   if (!user) {
//     return res.status(401).send('Tu cuenta no existe');
//   }

//   if (!bcrypt.compareSync(password, user.password)) {
//     return res.status(401).send('Contraseña equivocada');
//   }

//   const userId = user._id;
//   const token = jwt.sign({ exp: Math.floor(Date.now() / 1000) - 30, userId }, 'secreto');

//   req.session.user = {
//     username: user.username,
//     email,
//     rol: password === "adminCod3r123" ? "admin" : "usuario",
//   };

//   res.redirect('/');
// });


router.post('/login', passport.authenticate(
  "login",
  { 
    successRedirect: "/products", 
    failureRedirect: "/login",
    failureFlash: true,
  })
);

router.get('/github', passport.authenticate('github', { scope: ['user:email'] }));

router.get(
  '/githubcallback',
  passport.authenticate('github', { failureRedirect: '/login' }),
  (req, res) => {
    req.user = req.user;
    req.isLogged = true;
    res.redirect('/products');
  }
);

router.post('/logout', async (req, res) => {
  res.clearCookie("token");
  req.session.destroy(err => {
    if(!err) {
      res.redirect("/login")
    } else {
      res.send({ status: "error", body: err })
    }
  })
});

export default router;