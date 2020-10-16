import { Document, Schema, Model, model, Error } from "mongoose";
import bcrypt from "bcrypt-nodejs";
import { json } from "express";

export interface IUser extends Document {
  iUserID: number;
  iAccessTypeID: number;
  cName: string;
  cEmail:string;
  cUsername: string;
  cPassword: string;
  cPasswordHistory: JSON;
  cAccessToken: string;
  tAcExpiry: Date;
  cCompanyname:String;
  iVerified: number;
  cAddress: String;
  cCity: String;
  cPostalcode: String;
  cState: String;
  cPhone: String;
  cFax: String;
  iStatusID: number;
  iEnteredby: number;
  tEntered: Date;
  iUpdatedby: number;
  tUpdated: Date;
}

export const userSchema: Schema = new Schema({
  iUserID: Number,
  iAccessTypeID: Number,
  cName: String,
  cEmail:String,
  cUsername: String,
  cPassword: String,
  cPasswordHistory: JSON,
  cAccessToken: String,
  tAcExpiry: Date,
  cCompanyname: String,
  iVerified: Number,
  cAddress: String,
  cCity: String,
  cPostalcode: String,
  cState: String,
  cPhone: String,
  cFax: String,
  iStatusID: Number,
  iEnteredby: Number,
  tEntered: Date,
  iUpdatedby: Number,
  tUpdated: Date
});


userSchema.pre<IUser>("save", function save(next) {
  const user = this;

  bcrypt.genSalt(10, (err, salt) => {
    if (err) { return next(err); }
    bcrypt.hash(this.cPassword, salt, undefined, (err: Error, hash) => {
      if (err) { return next(err); }
      user.cPassword = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function (candidatePassword: string, callback: any) {
  bcrypt.compare(candidatePassword, this.cPassword, (err: Error, isMatch: boolean) => {
    callback(err, isMatch);
  });
};

export const User: Model<IUser> = model<IUser>("User", userSchema);
