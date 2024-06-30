import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

const auth = (req, res, next) => {
    try {
        const token = req.header("x-auth-token");
        console.log("Token received:", token); // Log token received

        if (!token) {
            return res.status(401).json({ error: "No authentication token, authorization denied." });
        }

        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                console.error("Error verifying token:", err); // Log verification error
                if (err.name === "TokenExpiredError") {
                    return res.status(401).json({ error: "Token expired, authorization denied." });
                } else if (err.name === "JsonWebTokenError") {
                    return res.status(401).json({ msg: "Invalid token, authorization denied." });
                } else {
                    return res.status(401).json({ error: "Token verification failed, authorization denied." });
                }
            } else {
                console.log("Token decoded:", decoded); // Log decoded token payload
                req.id = decoded.id;
                req.user_name = decoded.userName;
                next();
            }
        });
    } catch (err) {
        console.error("Error authenticating user:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
};

export default auth;

