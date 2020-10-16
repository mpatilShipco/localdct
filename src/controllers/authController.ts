import { NextFunction, Request, Response } from "express";
import { HELPER_AUTH_PASSPORT } from '../helpers/auth.helper';
import "../auth/passportHandler";

export class AuthController {

  public authenticateJWT(req: Request, res: Response, next: NextFunction) {
    HELPER_AUTH_PASSPORT.authenticate("jwt", function (err, oUser, info) {
      if (err) {
        console.log(err);
        return res.status(401).json({ status: "error", code: "unauthorized" });
      }
      if (!oUser) {
        return res.status(401).json({ status: "error", code: "unauthorized" });
      } else {
        return next();
      }
    })(req, res, next);
  }

  public authorizeJWT(req: Request, res: Response, next: NextFunction) {
    HELPER_AUTH_PASSPORT.authenticate("jwt", function (err, oUser, jwtToken) {
      if (err) {
        console.log(err);
        return res.status(401).json({ status: "error", code: "unauthorized" });
      }
      if (!oUser) {
        return res.status(401).json({ status: "error", code: "unauthorized" });
      } else {
        const scope = req.baseUrl.split("/").slice(-1)[0];
        const authScope = jwtToken.scope;
        if (authScope && authScope.indexOf(scope) > -1) {
          return next();
        }
        else {
          return res.status(401).json({ status: "error", code: "unauthorized" });
        }
      }
    })(req, res, next);
  }


}

