import { HELPER_AUTH_BCRYPT,HELPER_AUTH_JSONWEBTOKEN,HELPER_AUTH_PASSPORT } from '../helpers/auth.helper';
import { NextFunction, Request, Response } from "express";
import "../auth/passportHandler";
import { HELPER_MODEL_REQUIRED_USER } from '../helpers/model.required.helper';
import { JWT_SECRET } from "../util/secrets";
import { HELPER_BASIC_MOMENT } from '../helpers/basic.helper';

export class UserController {

  public async registerUser(req: Request, res: Response): Promise<void> {
    const hashedPassword = HELPER_AUTH_BCRYPT.hashSync(req.body.cPassword, HELPER_AUTH_BCRYPT.genSaltSync(10));
    var tCurrentTimestamp = new Date();
    let tCurrentDateTime = HELPER_BASIC_MOMENT.utc(tCurrentTimestamp).format("YYYY-MM-DD HH:mm:ss");
    let tAcExpiry = HELPER_BASIC_MOMENT.utc(tCurrentTimestamp).add(3, 'M').format("YYYY-MM-DD HH:mm:ss");
    const cAccessToken = HELPER_AUTH_JSONWEBTOKEN.sign({ cUsername: req.body.cUsername, scope : req.body.scope }, JWT_SECRET);

    await HELPER_MODEL_REQUIRED_USER.create({
      iAccessTypeID: 0,
      cName: req.body.cName,
      cEmail: req.body.cEmail,
      cUsername: req.body.cUsername,
      cPassword: hashedPassword,
      cAccessToken: cAccessToken,
      tAcExpiry: tAcExpiry,
      cCompanyname: req.body.cCompanyname,
      cAddress: req.body.cAddress,
      cCity: req.body.cCity,
      cPostalcode: req.body.cPostalcode,
      cState: req.body.cState,
      cPhone: req.body.cPhone,
      cFax: req.body.cFax,
      tEntered: tCurrentDateTime
    });
    
    res.status(200).send({ cAccessToken: cAccessToken });
  }

  public authenticateUser(req: Request, res: Response, next: NextFunction) {
    HELPER_AUTH_PASSPORT.authenticate("local", function (err, oUser, info) {
      // no async/await because passport works only with callback ..
      if (err) return next(err);
      if (!oUser) {
        return res.status(401).json({ status: "error", code: "unauthorized" });
      } else {
        const token = HELPER_AUTH_JSONWEBTOKEN.sign({ cUsername: oUser.cUsername }, JWT_SECRET);
        res.status(200).send({ token: token });
      }
    });
  }

}