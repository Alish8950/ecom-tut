import express from 'express'
import { adminLogin, loginUser, registerUser } from '../controllers/userController.js';


const userRouter = express.Router();

userRouter.post('/register', registerUser);
userRouter.post('/login', loginUser);
userRouter.post('/login', adminLogin);

export default userRouter;