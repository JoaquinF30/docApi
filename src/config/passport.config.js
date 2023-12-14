import passport from 'passport';
import local from 'passport-local';
import GitHubStrategy from 'passport-github2';
import { userModel } from "../dao/models/user.model.js";
import { isValidPassword, createHash, cookieExtractor } from '../utils.js';
import config from "./config.js"
import jwt from 'passport-jwt';

const LocalStrategy = local.Strategy;
const JWTStrategy = jwt.Strategy;
const ExtractJWT = jwt.ExtractJwt;

const initializePassport = () => {
  passport.use('register', new LocalStrategy({ passReqToCallback: true, usernameField: 'email' }, async (req, username, password, done) => {
        const { username: userInput } = req.body;
        try {
          const userExists = await userModel.findOne({ email: username });

          if (userExists) {
            return done("El usuario ya existe", false);
          }

          const user = await userModel.create({
            username: userInput,
            email: username,
            password: createHash(password),
          });

          return done(null, user);
        } catch (error) {
          return done("Error al obtener el usuario: " + error)
        }
      }
    )    
  );

  passport.serializeUser((user, done) => {
    done(null, user._id);
  });
  
  passport.deserializeUser(async (id, done) => {
      const user = await userModel.findById(id);
      done(null, user);
  });

  passport.use(
    'jwt',
    new JWTStrategy(
      {
        jwtFromRequest: ExtractJWT.fromExtractors([cookieExtractor]),
        secretOrKey: 'secreto',
      },
      async (jwt_payload, done) => {
        try {
          return done(null, jwt_payload);
        } catch (error) {
          return done(error);
        }
      }
    )
  );

  // passport.use('login', new LocalStrategy({ usernameField: 'email',  }, async (username, password, done) => {
  //   try {
  //       const user = await userModel.findOne({ email: username }).lean();
  //       if (!user) {
  //         return done(null, false);
  //       }

  //       if (!isValidPassword(user, password)) {
  //         return done(null, false);
  //       }

  //       return done(null, user);
  //   } catch (error) {
  //       return done(error);
  //   }})
  // );

  passport.use(
    'github',
    new GitHubStrategy(
      {
        clientID: config.github.clientId,
        clientSecret: config.github.secret,
        callbackURL: 'http://localhost:8080/api/githubcallback',
        scope: ['user:email'],
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails[0].value;
          const user = await userModel.findOne({ email });
          if (!user) {
            const newUser = await userModel.create({
              username: profile._json.login,
              password: '',
              email,
            });

            done(null, newUser);
          } else {
            done(null, user);
          }
        } catch (error) {
          done(error);
        }
      }
    )
  );

};

export default initializePassport;