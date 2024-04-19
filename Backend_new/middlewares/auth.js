import { User } from "../models/userSchema.js";
import { catchAsyncErrors } from "./catchAsyncError.js";
import ErrorHandler from "./error.js";
import jwt from "jsonwebtoken";

const isAuthenticated = async (req, res, next) => {
  const isAuthenticated = req.headers.authorization;
  if (!isAuthenticated || !isAuthenticated.startsWith("Bearer")) {
    next("Auth Failed");
  }
  const token = isAuthenticated.split(" ")[1];
  try {
    const payload = JWT.verify(token, process.env.JWT_SECRET);
    req.user = { userId: payload.userId };
    next();
  } catch (error) {
    next("Auth Failed");
  }
};
export default isAuthenticated;

