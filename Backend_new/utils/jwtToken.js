import jwt from "jsonwebtoken";

export const sendToken = (user, statusCode, res, message) => {
  console.log("User",user);
  console.log(user);
  const payload = {user:user.name,email:user.email,role:user.role}

  const token = jwt.sign(payload, "bO7ElGE70z2gNaJvh2dckVKvKZw", {
    expiresIn: '1h'
  });

 
  // const options = {
  //   expires: new Date(
  //     Date.now() + process.env.COOKIE_EXPIRE * 24 * 60 * 60 * 1000
  //   ),
  //   httpOnly: true, // Set httpOnly to true
  // };

  res.status(statusCode).cookie("token", token).json({
    success: true,
    message,
    role : user.role,
    token,
  });
};

export const decryptToken = (token) =>{
  //TODO: try catch. 
  const payload = jwt.verify(token,"bO7ElGE70z2gNaJvh2dckVKvKZw");
  return payload;
// return payload;
}
