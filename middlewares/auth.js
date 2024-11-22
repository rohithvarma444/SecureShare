import jwt from 'jsonwebtoken';

const auth = async (req, res, next) => {
    try {
        // Get token from header
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({
                success: false,
                message: "No authentication token found"
            });
        }

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Add user info to request
        req.user = {
            id: decoded.id,
            name: decoded.name,
        };

        next();
    } catch (error) {
        console.error('Auth Middleware Error:', error);
        return res.status(401).json({
            success: false,
            message: "Authentication failed",
            errorDetails: error.message
        });
    }
};

export default auth;
