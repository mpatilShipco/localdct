import passport from "passport";
import passportLocal from "passport-local";
// import passportApiKey from "passport-headerapikey";
import passportJwt from "passport-jwt";
import { HELPER_MODEL_REQUIRED_USER } from '../helpers/model.required.helper';
import { JWT_SECRET } from "../util/secrets";

const LocalStrategy = passportLocal.Strategy;
const JwtStrategy = passportJwt.Strategy;
const ExtractJwt = passportJwt.ExtractJwt;

passport.use(new LocalStrategy({ usernameField: "cUsername" }, (cUsername, cPassword, done) => {
  HELPER_MODEL_REQUIRED_USER.findOne({ cUsername: cUsername.toLowerCase() }, (err, oUser: any) => {
    if (err) { return done(err); }
    if (!oUser) {
      return done(undefined, false, { message: `cUsername ${cUsername} not found.` });
    }
    oUser.comparePassword(cPassword, (err: Error, isMatch: boolean) => {
      if (err) { return done(err); }
      if (isMatch) {
        return done(undefined, oUser);
      }
      return done(undefined, false, { message: "Invalid Username or password." });
    });
  });
}));

passport.use(new JwtStrategy(
  {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: JWT_SECRET
  }, function (jwtToken, done) {
    HELPER_MODEL_REQUIRED_USER.findOne({ cUsername: jwtToken.cUsername }, function (err, oUser) {
      if (err) { return done(err, false); }
      if (oUser) {
        return done(undefined, oUser , jwtToken);
      } else {
        return done(undefined, false);
      }
    });
  }));


