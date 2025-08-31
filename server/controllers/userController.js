import userModel from "../models/userModel.js";

export const getUserData = async (req, res) => {
    try {
        // const { userId } = req.body;

        const user = await userModel.findById(req.userId);

        if(!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        res.json({ 
            success: true, 
            message: 'User data fetched successfully', 
            userData: {
                username: user.username,
                isVerified: user.isVerified,
            } 
        });

    } catch (error) {
        res.json({ success: false, message: 'Server error' });
    }
}