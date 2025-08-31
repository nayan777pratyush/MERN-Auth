import jwt from 'jsonwebtoken';

const userAuth = async (req, res, next) => {
    const {token} = req.cookies;
    //console.log(token);

    if(!token) {
        return res.json({ success: false, message: 'No token, authorization denied' });
    }

    try {
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);

        if(tokenDecode.id) {
            //console.log(tokenDecode);
            //console.log(tokenDecode.id);
            req.userId = tokenDecode.id;
        
        } else {
            return res.json({ success: false, message: 'Not Authorized. Login Again' });
        }
        next();
 
    } catch (error) {
        res.json({ success: false, message: 'Token is not valid' });
    }
}

export default userAuth;

