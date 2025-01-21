import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

export const protectRoute = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;

    if (!token) {
      console.log("No token provided");
      return res.status(401).json({ message: "Unauthorized - No Token Provided" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded) {
      console.log("Invalid token");
      return res.status(401).json({ message: "Unauthorized - Invalid Token" });
    }

    // Make sure the decoded token has the expected property for userId
    console.log("Decoded token:", decoded);  // Log the decoded token to check the structure

    const user = await User.findById(decoded.userId).select("-password");

    if (!user) {
      console.log("User not found");
      return res.status(404).json({ message: "User not found" });
    }

    req.user = user;
    next();
  } catch (error) {
    console.log("Error in protectRoute middleware:", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};
